from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .models import Device


def authenticate_request(request):
    """
    Authenticate request using x-api-key and x-device-id headers
    Returns (is_authenticated, device, error_response)
    
    Authentication flow:
    1. Find the device by api_key (unique identifier)
    2. Verify device_id matches
    3. Check if device was logged out
    4. Check expiration
    """
    api_key = request.headers.get('x-api-key')
    device_id = request.headers.get('x-device-id')
    
    if not api_key or not device_id:
        return False, None, Response(
            {'error': 'Missing authentication headers'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    try:
        # Find device by api_key (which is unique)
        device = Device.objects.get(api_key=api_key)
        
        # Verify device_id matches
        if device.device_id != device_id:
            return False, None, Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if device was logged out due to login from another device
        if device.is_logged_out:
            return False, None, Response(
                {
                    'error': 'Session ended - logged in from another device',
                    'code': 'LOGGED_OUT_ANOTHER_DEVICE',
                    'logged_out_at': device.logged_out_at.isoformat() if device.logged_out_at else None
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if device is expired
        if device.expires_at < timezone.now():
            return False, None, Response(
                {'error': 'Device has expired'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return True, device, None
    except Device.DoesNotExist:
        return False, None, Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(['POST'])
def register_device(request):
    """
    Register or login a device
    POST /api/v1/auth/register
    Body: { "email": "user@example.com", "device_id": "device-xyz" }
    
    SINGLE DEVICE LOGIN ENFORCEMENT:
    When a user logs in from a new device, all other devices with the same email
    are automatically logged out. Only one active session per email is allowed.
    
    If a device was logged out by another device, it cannot re-register while
    the superseding device is still active. This prevents ping-pong loops.
    
    AUTOMATIC ACTIVATION TRANSFER:
    If the user already has an activated device, the new device automatically
    inherits the active status - no need to wait for admin approval again.
    """
    email = request.data.get('email')
    device_id = request.data.get('device_id')
    
    if not email or not device_id:
        return Response(
            {'error': 'Email and device_id are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Normalize email to lowercase for consistent lookups
    email = email.lower().strip()
    
    # Check if this device+email combination exists and was superseded
    # Apply a cooldown period to prevent automatic polling ping-pong
    # but still allow intentional re-login after the cooldown
    COOLDOWN_SECONDS = 60  # Device must wait 60 seconds before re-registering
    
    try:
        # Look up by BOTH device_id AND email (unique together)
        existing_device = Device.objects.get(device_id=device_id, email__iexact=email)
        
        # If this device was logged out by another device recently, apply cooldown
        if existing_device.is_logged_out and existing_device.logged_out_at:
            time_since_logout = (timezone.now() - existing_device.logged_out_at).total_seconds()
            
            # If within cooldown period, check if superseding device is still active
            if time_since_logout < COOLDOWN_SECONDS and existing_device.superseded_by:
                try:
                    superseding_device = Device.objects.get(device_id=existing_device.superseded_by)
                    
                    # If the superseding device is still active, block during cooldown
                    if not superseding_device.is_logged_out:
                        remaining_seconds = int(COOLDOWN_SECONDS - time_since_logout)
                        return Response(
                            {
                                'error': 'Session ended - you are logged in on another device',
                                'code': 'LOGGED_OUT_ANOTHER_DEVICE',
                                'message': f'This device was logged out because you logged in from another device. Please wait {remaining_seconds} seconds before logging in again.',
                                'logged_out_at': existing_device.logged_out_at.isoformat(),
                                'cooldown_remaining': remaining_seconds
                            },
                            status=status.HTTP_401_UNAUTHORIZED
                        )
                except Device.DoesNotExist:
                    # Superseding device no longer exists, allow re-registration
                    pass
            # If cooldown has passed, allow re-registration (will log out other device)
    except Device.DoesNotExist:
        existing_device = None
    
    # Check if we should auto-activate (transfer activation)
    # Auto-activate if this email was EVER approved on ANY device
    # This means once an email is approved by admin, it never needs approval again
    # We check is_active=True (which stays True even when device is logged out)
    # Also get the original expires_at date to preserve it (prevent expiry reset exploit)
    existing_active_device = Device.objects.filter(
        email__iexact=email,
        is_active=True
    ).order_by('created_at').first()  # Get the earliest activated device for this email
    
    should_auto_activate = existing_active_device is not None
    # Preserve the original expiry date from when the email was first activated
    original_expires_at = existing_active_device.expires_at if existing_active_device else None
    
    # LOGOUT all other devices with the same email
    other_devices = Device.objects.filter(email__iexact=email).exclude(device_id=device_id)
    logged_out_count = 0
    for other_device in other_devices:
        if not other_device.is_logged_out:
            other_device.logout_device(superseded_by_device_id=device_id)
            logged_out_count += 1
    
    # Now register/update the current device+email combination
    if existing_device:
        device = existing_device
        created = False
        
        # ALWAYS generate a new API key on registration
        device.api_key = Device.generate_api_key()
        
        # Clear logged out status and superseded_by
        device.is_logged_out = False
        device.logged_out_at = None
        device.superseded_by = None
        
        # Set last login time
        device.last_login_at = timezone.now()
        
        # PRESERVE the original expiry date if user was already activated
        # This prevents users from resetting their expiry by logging in from new devices
        if original_expires_at:
            device.expires_at = original_expires_at
        # Only set new expiry for users who were never activated (new users)
        elif not device.expires_at or device.expires_at < timezone.now():
            device.expires_at = timezone.now() + timezone.timedelta(days=30)
        # Otherwise keep the existing expires_at (don't reset it)
        
        # If user had an active device elsewhere with same email, transfer activation
        if should_auto_activate and not device.is_active:
            device.is_active = True
        
        device.save()
        
    else:
        # Create new device+email record
        # Each device_id + email combination is a separate record
        # This preserves old email registrations when a device uses a new email
        device = Device(
            device_id=device_id,
            email=email,
            is_active=should_auto_activate,  # Only auto-activate if another device with this email is already active
            last_login_at=timezone.now(),
        )
        
        # PRESERVE the original expiry date if user was already activated
        # This prevents users from resetting their expiry by logging in from new devices
        if original_expires_at:
            device.expires_at = original_expires_at
        # Otherwise the model's save() will set a new 30-day expiry for new users
        
        device.save()
        created = True
    
    # Also logout any OTHER registrations from the same device_id with different emails
    # This ensures single device login across all emails on this device
    Device.objects.filter(device_id=device_id).exclude(email__iexact=email).exclude(is_logged_out=True).update(
        is_logged_out=True,
        logged_out_at=timezone.now()
    )
    
    response_data = {
        'success': True,
        'message': 'Device registered successfully' if created else 'Device logged in successfully',
        'data': {
            'api_key': device.api_key,
            'device_id': device.device_id,
            'email': device.email,
            'is_active': device.is_active,
            'created_at': device.created_at.isoformat(),
            'expires_at': device.expires_at.isoformat(),
        }
    }
    
    # Include info about logged out devices
    if logged_out_count > 0:
        response_data['logged_out_other_devices'] = logged_out_count
        response_data['message'] = f'Logged in successfully. {logged_out_count} other device(s) logged out.'
    
    # Indicate if activation was automatically transferred
    if should_auto_activate:
        response_data['activation_transferred'] = True
    
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['GET'])
def check_device_status(request):
    """
    Check device activation status
    GET /api/v1/auth/check-status
    Headers: x-api-key, x-device-id
    
    Returns error with code 'LOGGED_OUT_ANOTHER_DEVICE' if this device
    was logged out due to login from another device.
    """
    is_authenticated, device, error_response = authenticate_request(request)
    
    if not is_authenticated:
        return error_response
    
    response_data = {
        'success': True,
        'is_active': device.is_active,
        'email': device.email,
        'device_id': device.device_id,
        'expires_at': device.expires_at.isoformat(),
    }
    
    return Response(response_data, status=status.HTTP_200_OK)

