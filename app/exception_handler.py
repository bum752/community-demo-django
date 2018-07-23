from rest_framework import views, status

def exception_handler(exc, context):
    response = views.exception_handler(exc, context)

    # print(response.status_code)
    # print(status.HTTP_401_UNAUTHORIZED)

    if response is not None:
        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            response.delete_cookie("jwttoken")
        return response
    else:
        return None
