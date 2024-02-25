from rest_framework.response import Response

def formatted_response(status, success, message, data=None):
    """
    Format the API response using Django REST Framework's Response class.
    
    Parameters:
        status (int): HTTP status code.
        success (bool): Indicates whether the operation was successful.
        message (str): A message describing the result.
        data (dict): Additional data to include in the response (default is None).
    
    Returns:
        Response: Formatted API response.
    """
    response_data = {
        'success': success,
        'message': message,
    }

    if data is not None:
        response_data['data'] = data

    return Response(response_data, status=status)
