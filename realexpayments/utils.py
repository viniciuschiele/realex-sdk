import hashlib
import requests

from datetime import datetime
from logging import getLogger
from uuid import uuid4
from .exceptions import RealexError


logger = getLogger(__name__)


class GenerationUtils(object):
    """
    Utils for the auto-generation of fields, for example the SHA1 hash.
    """

    @staticmethod
    def generate_hash(to_hash, secret):
        """
        Each message sent to Realex should have a hash, attached. For a message using the remote
        interface this is generated using the This is generated from the TIMESTAMP, MERCHANT_ID,
        ORDER_ID, AMOUNT, and CURRENCY fields concatenated together with "." in between each field.
        This confirms the message comes from the client and Generate a hash,
        required for all messages sent to IPS to prove it was not tampered with.
        :param str to_hash: The value to be hashed.
        :param str secret:
        :return str: The value hashed.
        """
        to_hash_first_pass = hashlib.sha1(to_hash.encode())
        to_hash_second_pass = to_hash_first_pass.hexdigest() + '.' + secret
        return hashlib.sha1(to_hash_second_pass.encode()).hexdigest()

    @staticmethod
    def generate_timestamp():
        """
        Generate the current datetimestamp in the string formaat (YYYYMMDDHHSS) required in a request to Realex.
        :return str: The current timestamp in YYYYMMDDHHSS format.
        """
        return datetime.now().strftime('%Y%m%d%H%M%S')

    @staticmethod
    def generate_order_id():
        """
        Order Id for a initial request should be unique per client ID. This method generates a unique
        order Id using the Python uuid4 method and then convert it to string.
        :return str: A unique id.
        """
        return str(uuid4())


class HttpUtils(object):
    """
    HTTP Utils class for dealing with HTTP and actual message sending.
    """

    HTTPS_PROTOCOL = 'https'

    @staticmethod
    def send_message(url, xml, timeout, only_allow_https, proxies):
        """
        Perform the actual send of the message, according to the HttpConfiguration, and get the response.
        This will also check if only HTTPS is allowed, based on the {@link HttpConfiguration}, and will
        throw a `RealexException` if HTTP is used when only HTTPS is allowed. A `RealexError`
        is also thrown if the response from Realex is not success (ie. if it's not 200 status code).
        :param str url: The realex url.
        :param str xml: The xml to be sent.
        :param int timeout: The timeout, in seconds, for sending a request to Realex.
        :param bool only_allow_https: `True` if only HTTPS is allowed for the endpoint.
        :param dict proxies: The proxies for `requests`.
        :return Response: The response instance.
        """
        # Confirm protocol is HTTPS (ie. secure) if such is configured
        if only_allow_https:
            if not url.lower().startswith(HttpUtils.HTTPS_PROTOCOL):
                logger.error('Protocol must be ' + HttpUtils.HTTPS_PROTOCOL)
                raise RealexError('Protocol must be ' + HttpUtils.HTTPS_PROTOCOL)
        else:
            logger.warn('Allowed send message over HTTP. This should NEVER be allowed in a production environment.')

        try:
            logger.debug('Executing HTTP Post message to: ' + url)
            headers = {'Content-Type': 'application/xml'}
            response = requests.post(url, data=xml, headers=headers, timeout=timeout, proxies=proxies)

            logger.debug('Checking the HTTP response status code.')
            if response.status_code != 200:
                raise RealexError('Unexpected http status code [' + str(response.status_code) + ']')

            logger.debug('Converting HTTP entity (the xml response) back into a string.')
            return response.content.decode()
        except Exception as e:
            logger.exception('Exception communicating with Realex.')
            raise RealexError('Exception communicating with Realex.', e)


class ResponseUtils(object):
    """
    Utils class offering methods which act on the Realex response.
    """

    # Realex error result codes in the range 3xx to 5xx will not return a full response message.
    # Instead a short response will be returned with only the result code and message populated.
    RESULT_CODE_PREFIX_ERROR_RESPONSE_START = 3

    @staticmethod
    def is_basic_response(result):
        """
        Realex responses can be basic or full. A basic response indicates the request could not
        be processed. In this case a {@link RealexServerException} will be thrown by the SDK containing the
        result code and message from the response.

        A full response indicates the request could be processed and the response object will return fully populated.

        Please note, full responses may still contain errors e.g. Bank errors (1xx). The result code should be
        checked for success. For example a full response with a result code of 101 will not throw an exception and will return
        a fully populated response object.

        :param str result: The result form the response.
        :return bool: `True` if it is a basic response otherwise `False`.
        """
        try:
            initial_number = int(result[0:1])
            return initial_number >= ResponseUtils.RESULT_CODE_PREFIX_ERROR_RESPONSE_START
        except Exception as e:
            logger.exception('Error parsing result %s', result)
            raise RealexError('Error parsing result.', e)
