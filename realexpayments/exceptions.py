"""
This module provides the exceptions thrown by Realex.
"""


class RealexError(Exception):
    """
    An exception class for general Realex SDK errors.
    All other SDK exceptions will extend this class.
    """
    pass


class RealexServerError(RealexError):
    """
    This exception will be thrown when an error occurs
    on the Realex server when attempting to process the request.

    :param str timestamp: The timestamp of the request/response.
    :param str order_id: The order Id of the request/response.
    :param str error_code: The error code returned from Realex.
    :param str message: The error message returned from Realex.
    """
    def __init__(self, timestamp, order_id, error_code, message):
        self.timestamp = timestamp
        self.order_id = order_id
        self.error_code = error_code
        self.message = message
