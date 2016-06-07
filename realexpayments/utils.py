"""
This module provides several util classes.
"""

import hashlib

from datetime import datetime
from logging import getLogger
from requests import sessions
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
    def send_message(url, xml, session, timeout, only_allow_https, proxies):
        """
        Perform the actual send of the message and get the response.
        This will also check if only HTTPS is allowed and will throw a `RealexError`
        if HTTP is used when only HTTPS is allowed. A `RealexError`
        is also thrown if the response from Realex is not success (ie. if it's not 200 status code).
        :param str url: The realex url.
        :param str xml: The xml to be sent.
        :param Session session: The requests' session.
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

            own_session = session is None

            if own_session:
                session = sessions.Session()

            try:
                response = session.post(url, data=xml, headers=headers, timeout=timeout, proxies=proxies)
            finally:
                if own_session:
                    session.close()

            logger.debug('Checking the HTTP response status code.')
            if response.status_code != 200:
                raise RealexError('Unexpected http status code [' + str(response.status_code) + ']')

            logger.debug('Converting HTTP entity (the xml response) back into a string.')
            return response.content.decode()
        except Exception as e:
            logger.exception('Exception communicating with Realex.')
            raise RealexError('Exception communicating with Realex.', e)


class RequestUtils(object):
    """
    Utils class offering methods which act on the Realex request.
    """

    @staticmethod
    def format_amount(amount):
        """
        Convert the amount in the smallest unit of the required currency
        (For example: 2000=20 euro, dollar or pounds).
        :param int|float amount: The amount to be converted.
        :return str: The amount as string.
        """
        return str(int(amount * 100))

    @staticmethod
    def format_expire_date(expiry_month, expiry_year):
        """
        Convert the given month and year in the format MMYY.
        :param int expiry_month: The month.
        :param int expiry_year: The year.
        :return str: The expiry date in the format MMYY.
        """
        return ('%02d' % expiry_month) + ('%02d' % expiry_year)

    @staticmethod
    def get_card_not_enrolled_eci(card_type):
        """
        Get the card not enrolled ECI for the given card type.
        https://resourcecentre.realexpayments.com/pdf/RealControl%20Reporting%20-%20User%20Guide%20v1.0.pdf
        :param str card_type: The card type. e.g: VISA, MC, AMEX,...
        :return str: The ECI.
        """
        if card_type == 'VISA':
            return '6'

        if card_type == 'MC':
            return '1'

        raise Exception('Only VISA and MC support 3DSecure.')

    @staticmethod
    def get_non_3dsecure_transaction_eci(card_type):
        """
        Get the non 3d secure transaction ECI for the given card type.
        https://resourcecentre.realexpayments.com/pdf/RealControl%20Reporting%20-%20User%20Guide%20v1.0.pdf
        :param str card_type: The card type. e.g: VISA, MC, AMEX,...
        :return str: The ECI.
        """
        if card_type == 'VISA':
            return '7'

        if card_type == 'MC':
            return '0'

        raise Exception('Only VISA and MC support 3DSecure.')

    @staticmethod
    def is_3dsecure_supported(card_type):
        """
        Get the value that indicates whether the card type supports 3D Secure.
        :param str card_type: The card type. e.g: VISA, MC, AMEX,...
        :return: `True` if the card type supports 3D Secure.
        """
        return card_type != 'AMEX'


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
