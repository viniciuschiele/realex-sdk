import hashlib
import requests

from datetime import datetime
from logging import getLogger
from uuid import uuid4
from .exceptions import RealexError


logger = getLogger(__name__)


class GenerationUtils(object):
    @staticmethod
    def generate_hash(to_hash, secret):
        to_hash_first_pass = hashlib.sha1(to_hash.encode())
        to_hash_second_pass = to_hash_first_pass.hexdigest() + '.' + secret
        return hashlib.sha1(to_hash_second_pass.encode()).hexdigest()

    @staticmethod
    def generate_timestamp():
        return datetime.now().strftime('%Y%m%d%H%M%S')

    @staticmethod
    def generate_order_id():
        return str(uuid4())


class HttpUtils(object):
    HTTPS_PROTOCOL = 'https'

    @staticmethod
    def send(url, xml, timeout, only_allow_https, proxies):
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
        # } catch (IOException ioe) {
        except Exception as e:
            logger.exception('Exception communicating with Realex.')
            raise RealexError('Exception communicating with Realex.', e)


class ResponseUtils(object):
    RESULT_CODE_PREFIX_ERROR_RESPONSE_START = 3

    @staticmethod
    def is_basic_response(result):
        """
        Realex responses can be basic or full. A basic response indicates the request could not
        be processed. In this case a {@link RealexServerException} will be thrown by the SDK containing the
        result code and message from the response.

        A full response indicates the request could be processed and the response object will return fully populated.
Add triggers for provisioninggit+https://github.com/viniciuschiele/realex-client
        Please note, full responses may still contain errors e.g. Bank errors (1xx). The result code should be
        checked for success. For example a full response with a result code of 101 will not throw an exception and will return
        a fully populated response object.
        """
        try:
            initial_number = int(result[0:1])
            return initial_number >= ResponseUtils.RESULT_CODE_PREFIX_ERROR_RESPONSE_START
        except Exception as e:
            logger.exception('Error parsing result %s', result)
            raise RealexError('Error parsing result.', e)
