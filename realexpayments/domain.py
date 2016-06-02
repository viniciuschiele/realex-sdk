from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from .utils import GenerationUtils


class Address(object):
    def __init__(self, type=None, code=None, country=None):
        self.type = type
        self.code = code
        self.country = country

    def to_xml_element(self, parent):
        element = SubElement(parent, 'address')
        element.set('type', self.type)

        sub_element = SubElement(element, 'code')
        sub_element.text = self.code

        sub_element = SubElement(element, 'country')
        sub_element.text = self.country


class AddressType(object):
    none = ''
    shipping = 'shipping'
    billing = 'billing'


class Amount(object):
    def __init__(self, currency=None, amount=None):
        self.currency = currency
        self.amount = amount

    def to_xml_element(self, parent):
        element = SubElement(parent, 'amount')
        element.set('currency', self.currency)
        element.text = self.amount


class AutoSettle(object):
    def __init__(self, flag=None):
        self.flag = flag

    def to_xml_element(self, parent):
        element = SubElement(parent, 'autosettle')
        element.set('flag', self.flag)


class AutoSettleFlag(object):
    true = '1'
    false = '0'
    multi = 'multi'


class Card(object):
    def __init__(self, type=None, number=None, card_holder_name=None, expiry_date=None, issue_number=None, cvn=None):
        self.type = type
        self.number = number
        self.card_holder_name = card_holder_name
        self.expiry_date = expiry_date
        self.issue_number = issue_number
        self.cvn = cvn

    def to_xml_element(self, parent):
        element = SubElement(parent, 'card')

        sub_element = SubElement(element, 'type')
        sub_element.text = self.type

        sub_element = SubElement(element, 'number')
        sub_element.text = self.number

        sub_element = SubElement(element, 'expdate')
        sub_element.text = self.expiry_date

        sub_element = SubElement(element, 'chname')
        sub_element.text = self.card_holder_name

        sub_element = SubElement(element, 'issueno')
        sub_element.text = self.issue_number

        if self.cvn:
            self.cvn.to_xml_element(element)


class CardType(object):
    visa = 'VISA'
    mastercard = 'MC'
    amex = 'AMEX'
    cb = 'CB'
    diners = 'DINERS'
    jcb = 'JCB'


class Cvn(object):
    def __init__(self, number=None, presence_indicator=None):
        self.number = number
        self.presence_indicator = presence_indicator

    def to_xml_element(self, parent):
        element = SubElement(parent, 'cvn')

        sub_element = SubElement(element, 'number')
        sub_element.text = self.number

        sub_element = SubElement(element, 'presind')
        sub_element.text = self.presence_indicator


class PresenceIndicator(object):
    present = '1'
    illegible = '2'
    not_on_card = '3'
    not_requested = '4'


class CardIssuer(object):
    def __init__(self, bank=None, country=None, country_code=None, region=None):
        self.bank = bank
        self.country = country
        self.country_code = country_code
        self.region = region

    @staticmethod
    def from_xml_element(element):
        card_issuer = CardIssuer()

        sub_element = element.find('bank')
        if sub_element is not None:
            card_issuer.bank = sub_element.text

        sub_element = element.find('country')
        if sub_element is not None:
            card_issuer.country = sub_element.text

        sub_element = element.find('countrycode')
        if sub_element is not None:
            card_issuer.country_code = sub_element.text

        sub_element = element.find('region')
        if sub_element is not None:
            card_issuer.region = sub_element.text

        return card_issuer


class Mpi(object):
    def __init__(self, cavv=None, xid=None, eci=None):
        self.cavv = cavv
        self.xid = xid
        self.eci = eci

    def to_xml_element(self, parent):
        element = SubElement(parent, 'mpi')
        sub_element = SubElement(element, 'cavv')
        sub_element.text = self.cavv

        sub_element = SubElement(element, 'xid')
        sub_element.text = self.xid

        sub_element = SubElement(element, 'eci')
        sub_element.text = self.eci


class Comment(object):
    def __init__(self, id=None, comment=None):
        self.id = id
        self.comment = comment

    def to_xml_element(self, parent):
        element = SubElement(parent, 'comment')
        element.set('id', self.id)
        element.text = self.comment


class Recurring(object):
    def __init__(self, type=None, sequence=None, flag=None):
        self.type = type
        self.sequence = sequence
        self.flag = flag

    def to_xml_element(self, parent):
        element = SubElement(parent, 'recurring')
        element.set('type', self.type)
        element.set('sequence', self.sequence)
        element.set('flag', self.flag)


class RecurringType(object):
    none = ''
    variable = 'variable'
    fixed = 'fixed'


class RecurringSequence(object):
    none = ''
    first = 'first'
    subsequent = 'subsequent'
    last = 'last'


class RecurringFlag(object):
    none = ''
    zero = '0'
    one = '1'
    two = '2'


class TssInfo(object):
    def __init__(self, customer_number=None, product_id=None, variable_reference=None,
                 customer_ip_address=None, addresses=None):
        self.customer_number = customer_number
        self.product_id = product_id
        self.variable_reference = variable_reference
        self.customer_ip_address = customer_ip_address
        self.addresses = addresses

    def to_xml_element(self, parent):
        element = SubElement(parent, 'tssinfo')

        sub_element = SubElement(element, 'custnum')
        sub_element.text = self.customer_number

        sub_element = SubElement(element, 'prodid')
        sub_element.text = self.product_id

        sub_element = SubElement(element, 'varref')
        sub_element.text = self.variable_reference

        sub_element = SubElement(element, 'custipaddress')
        sub_element.text = self.customer_ip_address

        if self.addresses:
            for address in self.addresses:
                address.to_xml_element(element)


class TssResult(object):
    def __init__(self, result=None, checks=None):
        self.result = result
        self.checks = checks

    @staticmethod
    def from_xml_element(element):
        tss_result = TssResult()

        sub_element = element.find('result')
        if sub_element is not None:
            tss_result.result = sub_element.text

        sub_elements = element.findall('check')
        tss_result.checks = []
        for sub_element in sub_elements:
            tss_result.checks.append(TssResultCheck.from_xml_element(sub_element))

        return tss_result


class TssResultCheck(object):
    def __init__(self, id=None, value=None):
        self.id = id
        self.value = value

    @staticmethod
    def from_xml_element(element):
        check = TssResultCheck()

        if 'id' in element.attrib:
            check.id = element.attrib['id']

        check.value = element.text

        return check


class Request(object):
    def generate_defaults(self, secret):
        raise NotImplementedError()

    def response_from_xml(self, xml):
        raise NotImplementedError()

    def to_xml(self):
        raise NotImplementedError()


class Response(object):
    def is_hash_valid(self, secret):
        raise NotImplementedError()


class PaymentType(object):
    auth = 'auth'
    auth_mobile = 'auth-mobile'
    settle = 'settle'
    void = 'void'
    rebate = 'rebate'
    otb = 'otb'
    credit = 'credit'
    hold = 'hold'
    release = 'release'


class PaymentRequest(Request):
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get('timestamp')
        self.type = kwargs.get('type')
        self.merchant_id = kwargs.get('merchant_id')
        self.account = kwargs.get('account')
        self.channel = kwargs.get('channel')
        self.order_id = kwargs.get('order_id')
        self.currency = kwargs.get('currency')
        self.amount = kwargs.get('amount')
        self.card = kwargs.get('card')
        self.auto_settle = kwargs.get('auto_settle')
        self.comments = kwargs.get('comments')
        self.auth_code = kwargs.get('authcode')
        self.payments_reference = kwargs.get('payments_reference')
        self.mobile = kwargs.get('mobile')
        self.token = kwargs.get('token')
        self.mpi = kwargs.get('mpi')
        self.fraud_filter = kwargs.get('fraud_filter')
        self.recurring = kwargs.get('recurring')
        self.tss_info = kwargs.get('tss_info')
        self.refund_hash = kwargs.get('refund_hash')
        self.sha1hash = kwargs.get('sha1hash')

    def generate_defaults(self, secret):
        if self.timestamp is None:
            self.timestamp = GenerationUtils.generate_timestamp()

        if self.order_id is None:
            self.order_id = GenerationUtils.generate_order_id()

        if self.sha1hash is None:
            self.generate_hash(secret)

    def generate_hash(self, secret):
        """
        Create the security hash from a number of fields and the shared secret.
        """
        timestamp = self.timestamp or ''
        merchant_id = self.merchant_id or ''
        order_id = self.order_id or ''
        amount = ''
        currency = ''
        card_number = ''
        token = self.token or ''

        if self.amount:
            amount = self.amount.amount or ''
            currency = self.amount.currency or ''

        if self.card:
            card_number = self.card.number or ''

        if self.type == PaymentType.auth_mobile:
            to_hash = '.'.join((timestamp, merchant_id, order_id, '.', token))
        elif self.type == PaymentType.otb:
            to_hash = '.'.join((timestamp, merchant_id, order_id, card_number))
        else:
            to_hash = '.'.join((timestamp, merchant_id, order_id, amount, currency, card_number))

        self.sha1hash = GenerationUtils.generate_hash(to_hash, secret)

    def response_from_xml(self, xml):
        return PaymentResponse.from_xml(xml)

    def to_xml(self):
        root = Element('request')
        root.set('timestamp', self.timestamp)
        root.set('type', self.type)

        if self.merchant_id:
            element = SubElement(root, 'merchantid')
            element.text = self.merchant_id

        if self.channel:
            element = SubElement(root, 'channel')
            element.text = self.channel

        if self.order_id:
            element = SubElement(root, 'orderid')
            element.text = self.order_id

        if self.amount:
            self.amount.to_xml_element(root)

        if self.card:
            self.card.to_xml_element(root)

        if self.auto_settle:
            self.auto_settle.to_xml_element(root)

        if self.comments:
            element = SubElement(root, 'comments')
            for comment in self.comments:
                comment.to_xml_element(element)

        if self.auth_code:
            element = SubElement(root, 'auth_code')
            element.text = self.auth_code

        if self.payments_reference:
            element = SubElement(root, 'pasref')
            element.text = self.payments_reference

        if self.mobile:
            element = SubElement(root, 'mobile')
            element.text = self.mobile

        if self.token:
            element = SubElement(root, 'token')
            element.text = self.token

        if self.mpi:
            self.mpi.to_xml_element(root)

        if self.fraud_filter:
            element = SubElement(root, 'fraudfilter')
            element.text = self.fraud_filter

        if self.recurring:
            self.recurring.to_xml_element(root)

        if self.tss_info:
            self.tss_info.to_xml_element(root)

        if self.refund_hash:
            element = SubElement(root, 'refundhash')
            element.text = self.refund_hash

        if self.sha1hash:
            element = SubElement(root, 'sha1hash')
            element.text = self.sha1hash

        return tostring(root)


class PaymentResponse(Response):
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get('timestamp')
        self.merchant_id = kwargs.get('merchant_id')
        self.account = kwargs.get('account')
        self.order_id = kwargs.get('order_id')
        self.auth_code = kwargs.get('auth_code')
        self.result = kwargs.get('result')
        self.message = kwargs.get('message')
        self.payments_reference = kwargs.get('payments_reference')
        self.cvn_result = kwargs.get('cvn_result')
        self.time_taken = kwargs.get('time_taken')
        self.auth_time_taken = kwargs.get('auth_time_taken')
        self.acquirer_response = kwargs.get('acquirer_response')
        self.batch_id = kwargs.get('batch_id')
        self.card_issuer = kwargs.get('card_issuer')
        self.tss_result = kwargs.get('tss_result')
        self.avs_postcode_response = kwargs.get('avs_postcode_response')
        self.avs_address_response = kwargs.get('avs_address_response')
        self.sha1hash = kwargs.get('sha1hash')

    @staticmethod
    def from_xml(xml):
        root = fromstring(xml)

        response = PaymentResponse()

        if 'timestamp' in root.attrib:
            response.timestamp = root.attrib['timestamp']

        element = root.find('merchantid')
        if element is not None:
            response.merchant_id = element.text

        element = root.find('account')
        if element is not None:
            response.account = element.text

        element = root.find('orderid')
        if element is not None:
            response.order_id = element.text

        element = root.find('result')
        if element is not None:
            response.result = element.text

        element = root.find('authcode')
        if element is not None:
            response.auth_code = element.text

        element = root.find('message')
        if element is not None:
            response.message = element.text

        element = root.find('pasref')
        if element is not None:
            response.payments_reference = element.text

        element = root.find('cvnresult')
        if element is not None:
            response.cvn_result = element.text

        element = root.find('timetaken')
        if element is not None:
            response.time_taken = element.text

        element = root.find('authtimetaken')
        if element is not None:
            response.auth_time_taken = element.text

        element = root.find('acquirerresponse')
        if element is not None:
            response.acquirer_response = element.text

        element = root.find('batchid')
        if element is not None:
            response.batch_id = element.text

        element = root.find('cardissuer')
        if element is not None:
            response.card_issuer = CardIssuer.from_xml_element(element)

        element = root.find('tss')
        if element is not None:
            response.tss_result = TssResult.from_xml_element(element)

        element = root.find('avspostcoderesponse')
        if element is not None:
            response.avs_postcode_response = element.text

        element = root.find('avsaddressresponse')
        if element is not None:
            response.avs_address_response = element.text

        element = root.find('sha1hash')
        if element is not None:
            response.sha1hash = element.text

        return response

    def is_hash_valid(self, secret):
        """
        Validates the response from realex. Raises an exception if
        validation fails.
        """
        # for any null values and set them to empty string for hashing
        timestamp = self.timestamp or ''
        merchant_id = self.merchant_id or ''
        order_id = self.order_id or ''
        result = self.result or ''
        message = self.message or ''
        payments_reference = self.payments_reference or ''
        auth_code = self.auth_code or ''

        to_hash = '.'.join((timestamp, merchant_id, order_id, result, message, payments_reference, auth_code))

        expected_hash = GenerationUtils.generate_hash(to_hash, secret)
        return expected_hash == self.sha1hash


class ThreeDSecure(object):
    def __init__(self, status=None, eci=None, xid=None, cavv=None, algorithm=None):
        self.status = status
        self.eci = eci
        self.xid = xid
        self.cavv = cavv
        self.algorithm = algorithm

    @staticmethod
    def from_xml_element(element):
        threedsecure = ThreeDSecure()

        sub_element = element.find('status')
        if sub_element is not None:
            threedsecure.status = sub_element.text

        sub_element = element.find('eci')
        if sub_element is not None:
            threedsecure.eci = sub_element.text

        sub_element = element.find('xid')
        if sub_element is not None:
            threedsecure.xid = sub_element.text

        sub_element = element.find('cavv')
        if sub_element is not None:
            threedsecure.cavv = sub_element.text

        sub_element = element.find('algorithm')
        if sub_element is not None:
            threedsecure.algorithm = sub_element.text

        return threedsecure


class ThreeDSecureType(object):
    verify_enrolled = '3ds-verifyenrolled'
    verify_sig = '3ds-verifysig'


class ThreeDSecureRequest(Request):
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get('timestamp')
        self.type = kwargs.get('type')
        self.merchant_id = kwargs.get('merchant_id')
        self.account = kwargs.get('account')
        self.order_id = kwargs.get('order_id')
        self.amount = kwargs.get('amount')
        self.card = kwargs.get('car')
        self.pares = kwargs.get('pares')
        self.comments = kwargs.get('comments')
        self.sha1hash = kwargs.get('sha1hash')

    def generate_defaults(self, secret):
        if self.timestamp is None:
            self.timestamp = GenerationUtils.generate_timestamp()

        if self.order_id is None:
            self.order_id = GenerationUtils.generate_order_id()

        if self.sha1hash is None:
            self.generate_hash(secret)

    def generate_hash(self, secret):
        """
        Create the security hash from a number of fields and the shared secret.
        """
        timestamp = self.timestamp or ''
        merchant_id = self.merchant_id or ''
        order_id = self.order_id or ''
        amount = ''
        currency = ''
        card_number = ''

        if self.amount:
            amount = self.amount.amount or ''
            currency = self.amount.currency or ''

        if self.card:
            card_number = self.card.number or ''

        to_hash = '.'.join((timestamp, merchant_id, order_id, amount, currency, card_number))

        self.sha1hash = GenerationUtils.generate_hash(to_hash, secret)

    def response_from_xml(self, xml):
        return ThreeDSecureResponse.from_xml(xml)

    def to_xml(self):
        root = Element('request')
        root.set('timestamp', self.timestamp)
        root.set('type', self.type)

        element = SubElement(root, 'merchantid')
        element.text = self.merchant_id

        element = SubElement(root, 'account')
        element.text = self.account

        element = SubElement(root, 'orderid')
        element.text = self.order_id

        if self.amount:
            self.amount.to_xml_element(root)

        if self.card:
            self.card.to_xml_element(root)

        element = SubElement(root, 'pares')
        element.text = self.pares

        if self.comments:
            element = SubElement(root, 'comments')
            for comment in self.comments:
                comment.to_xml_element(element)

        element = SubElement(root, 'sha1hash')
        element.text = self.sha1hash

        return tostring(root)


class ThreeDSecureResponse(Response):
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get('timestamp')
        self.merchant_id = kwargs.get('merchant_id')
        self.account = kwargs.get('account')
        self.order_id = kwargs.get('order_id')
        self.result = kwargs.get('result')
        self.auth_code = kwargs.get('auth_code')
        self.message = kwargs.get('message')
        self.payments_reference = kwargs.get('payments_reference')
        self.time_taken = kwargs.get('time_taken')
        self.auth_time_taken = kwargs.get('auth_time_taken')
        self.pareq = kwargs.get('pareq')
        self.url = kwargs.get('url')
        self.enrolled = kwargs.get('enrolled')
        self.xid = kwargs.get('xid')
        self.threedsecure = kwargs.get('threedsecure')
        self.sha1hash = kwargs.get('sha1hash')

    @staticmethod
    def from_xml(xml):
        response = ThreeDSecureResponse()

        root = fromstring(xml)

        if 'timestamp' in root.attrib:
            response.timestamp = root.attrib['timestamp']

        element = root.find('merchantid')
        if element is not None:
            response.merchant_id = element.text

        element = root.find('account')
        if element is not None:
            response.account = element.text

        element = root.find('orderid')
        if element is not None:
            response.order_id = element.text

        element = root.find('result')
        if element is not None:
            response.result = element.text

        element = root.find('authcode')
        if element is not None:
            response.auth_code = element.text

        element = root.find('message')
        if element is not None:
            response.message = element.text

        element = root.find('pasref')
        if element is not None:
            response.payments_reference = element.text

        element = root.find('timetaken')
        if element is not None:
            response.time_taken = element.text

        element = root.find('authtimetaken')
        if element is not None:
            response.auth_time_taken = element.text

        element = root.find('pareq')
        if element is not None:
            response.pareq = element.text

        element = root.find('url')
        if element is not None:
            response.url = element.text

        element = root.find('enrolled')
        if element is not None:
            response.enrolled = element.text

        element = root.find('xid')
        if element is not None:
            response.xid = element.text

        element = root.find('threedsecure')
        if element is not None:
            response.threedsecure = ThreeDSecure.from_xml_element(element)

        element = root.find('sha1hash')
        if element is not None:
            response.sha1hash = element.text

        return response

    def is_hash_valid(self, secret):
        """
        Validates the response from realex. Raises an exception if
        validation fails.
        """
        # for any null values and set them to empty string for hashing
        timestamp = self.timestamp or ''
        merchant_id = self.merchant_id or ''
        order_id = self.order_id or ''
        result = self.result or ''
        message = self.message or ''
        payments_reference = self.payments_reference or ''
        auth_code = self.auth_code or ''

        to_hash = '.'.join((timestamp, merchant_id, order_id, result, message, payments_reference, auth_code))

        expected_hash = GenerationUtils.generate_hash(to_hash, secret)
        return expected_hash == self.sha1hash

