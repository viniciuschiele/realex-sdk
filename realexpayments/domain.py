"""
This module provides all the domain classes used by Realex.
"""

from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from .utils import GenerationUtils


class Address(object):
    """
    The Address of the customer.

    :param str type: The address type. Can be shipping or billing.
    :param str code: The ZIP|Postal code of the address. This can be checked against a table of high-risk area codes.
    :param str country: The country of the address. This can be checked against a table of high-risk countries.
    """
    def __init__(self, type=None, code=None, country=None):
        self.type = type
        self.code = code
        self.country = country

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('address')

        if self.type is not None:
            element.set('type', self.type)

        if self.code is not None:
            SubElement(element, 'code').text = self.code

        if self.country is not None:
            SubElement(element, 'country').text = self.country

        return element


class AddressType(object):
    """
    Enumeration representing the address type.
    """
    none = ''
    shipping = 'shipping'
    billing = 'billing'


class Country(object):
    """
    Domain object representing Country information to be passed to Realex.

    :param str code: The country code. The list of country codes is available in the realauth developers guide.
    :param str name: The country name.
    """
    def __init__(self, code=None, name=None):
        self.code = code
        self.name = name

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('country')

        if self.code is not None:
            element.set('code', self.code)

        if self.name is not None:
            element.text = self.name

        return element


class Amount(object):
    """
    Class representing the Amount in a Realex request.

    :param str currency: The type of currency, e.g. GBP (Sterling) or EUR (Euro)
    :param str amount: The amount should be in the smallest unit of the required currency
        (For example: 2000=20 euro, dollar or pounds).
    """
    def __init__(self, currency=None, amount=None):
        self.currency = currency
        self.amount = amount

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('amount', currency=self.currency)

        if self.currency is not None:
            element.set('currency', self.currency)

        element.text = self.amount
        return element


class AutoSettle(object):
    """
    Class representing the AutoSettle flag in a Realex request. If set to true (1),
    then the transaction will be included in today's settlement file. If set to false (0), then the
    transaction will be authorised but not settled. Merchants must manually settle delayed
    transactions within 28 days of authorisation.

    :param str flag: The AutoSettle flag value.
    """
    def __init__(self, flag=None):
        self.flag = flag

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('autosettle')

        if self.flag is not None:
            element.set('flag', self.flag)

        return element


class AutoSettleFlag(object):
    """
    Enumeration representing the auto settle flag (true (1), false (0) or multi-settle (MULTI)).
    """
    true = '1'
    false = '0'
    multi = 'MULTI'


class Card(object):
    """
    Represents the card which is required in AUTH requests.

    :param str type: The card type used in the transaction.
    :param str number: The card number used for the transaction.
    :param str card_holder_name: The card holder's name.
    :param str expiry_date: The card expiry date, in the format MMYY, which must be a date in the future.
    :param int issue_number: The card issue number.
    :param Cvn cvn: The card verification number.
    :param str ref: The reference for this card (Card Storage).
        This must be unique within the Payer record if you are adding multiple
        cards, but it does not need to be unique in relation to other Payers.
    :param str payer_ref: The payer ref for this customer (Card Storage).
    """
    def __init__(self, type=None, number=None, card_holder_name=None,
                 expiry_date=None, issue_number=None, cvn=None,
                 ref=None, payer_ref=None):
        self.type = type
        self.number = number
        self.card_holder_name = card_holder_name
        self.expiry_date = expiry_date
        self.issue_number = issue_number
        self.cvn = cvn
        self.ref = ref
        self.payer_ref = payer_ref

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('card')

        if self.ref is not None:
            SubElement(element, 'ref').text = self.ref

        if self.payer_ref is not None:
            SubElement(element, 'payerref').text = self.payer_ref

        if self.type is not None:
            SubElement(element, 'type').text = self.type

        if self.number is not None:
            SubElement(element, 'number').text = self.number

        if self.expiry_date is not None:
            SubElement(element, 'expdate').text = self.expiry_date

        if self.card_holder_name is not None:
            SubElement(element, 'chname').text = self.card_holder_name

        if self.issue_number is not None:
            SubElement(element, 'issueno').text = self.issue_number

        if self.cvn is not None:
            element.append(self.cvn.to_xml_element())

        return element


class CardType(object):
    """
    Enumeration representing the card type.
    """
    visa = 'VISA'
    mastercard = 'MC'
    amex = 'AMEX'
    cb = 'CB'
    diners = 'DINERS'
    jcb = 'JCB'


class Cvn(object):
    """
    Class representing the card verification details.

    :param str number: A three-digit number on the reverse of the card.
        It is called the CVC for VISA and the CVV2 for MasterCard.
        For an AMEX card, it is a four digit number.
    :param str presence_indicator: The presence indicator.
    """
    def __init__(self, number=None, presence_indicator=None):
        self.number = number
        self.presence_indicator = presence_indicator

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('cvn')

        if self.number is not None:
            SubElement(element, 'number').text = self.number

        if self.presence_indicator is not None:
            SubElement(element, 'presind').text = self.presence_indicator

        return element


class CvnNumber(object):
    """
    Domain object representing PaymentData CVN number information to be passed to
    Realex Card Storage for Receipt-in transactions.
    Contains the CVN number for the stored card.

    :param str number: A three-digit number on the reverse of the card.
        It is called the CVC for VISA and the CVV2 for MasterCard.
        For an AMEX card, it is a four digit number.
    """
    def __init__(self, number=None):
        self.number = number

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('cvn')

        if self.number is not None:
            SubElement(element, 'number').text = self.number

        return element


class PresenceIndicator(object):
    """
    Enumeration of the possible presence indicator values.
    """
    present = '1'
    illegible = '2'
    not_on_card = '3'
    not_requested = '4'


class CardIssuer(object):
    """
    Class representing details of the card holder's bank (if available).

    :param str bank: The Bank Name (e.g. First Data Bank).
    :param str country: The Bank Country in English (e.g. UNITED STATES).
    :param str country_code: The country code of the issuing bank (e.g. US).
    :param str region: The region the card was issued (e.g. US)
        Can be MEA (Middle East/Asia), LAT (Latin America), US (United States), EUR (Europe), CAN (Canada),
        A/P (Asia/Pacific).
    """
    def __init__(self, bank=None, country=None, country_code=None, region=None):
        self.bank = bank
        self.country = country
        self.country_code = country_code
        self.region = region

    @staticmethod
    def from_xml_element(element):
        """
        Load the current instance with the given XML `Element` object.
        :param Element element: The XML element.
        """
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
    """
    Domain object representing MPI (realmpi) information to be passed to Realex.
    RealMPI is Realex's product to implement card scheme-certified payer authentication via the bank
    and the 3D Secure system (Verified by Visa for Visa, Secure Code for Mastercard and SafeKey for Amex).

    :param str cavv: The CAVV(Visa)/UCAF(Mastercard) if present.
    :param str xid: The XID.
    :param str eci: The e-commerce indicator.
        5 or 2 = Fully secure, card holder enrolled.
        6 or 1 = Merchant secure, card holder not enrolled or attempt ACS server was used.
        7 or 0 = Transaction not secure.
    """
    def __init__(self, cavv=None, xid=None, eci=None):
        self.cavv = cavv
        self.xid = xid
        self.eci = eci

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('mpi')

        if self.cavv is not None:
            SubElement(element, 'cavv').text = self.cavv

        if self.xid is not None:
            SubElement(element, 'xid').text = self.xid

        if self.eci is not None:
            SubElement(element, 'eci').text = self.eci

        return element


class Comment(object):
    """
    Class representing a Comment in a Realex request.

    :param int id: The comment ID (1 or 2)
    :param str comment: The text comment.
    """
    def __init__(self, id=None, comment=None):
        self.id = id
        self.comment = comment

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('comment')

        if self.id is not None:
            element.set('id', str(self.id))

        element.text = self.comment
        return element


class Payer(object):
    """
    Domain object representing Payer information to be passed to Realex.

    :param str type: The payer type can be used to identify the category of the Payer.
    :param str ref: The payer ref is the reference for this customer. It must be unique.
    :param str title: The title of the payer.
    :param str first_name: The first name of the payer.
    :param str surname: The surname of the payer.
    :param str company: The company name.
    :param PayerAddress address: The object containing the payer address.
    :param PhoneNumbers phone_numbers: The object containing the payer phone numbers.
    :param str email: The email of the payer.
    :param list[Comment] comments: The list of comment objects to be passed in request.
            Optionally, up to two comments can be associated with any payer.
    """
    def __init__(self, type=None, ref=None, title=None, first_name=None, surname=None, company=None,
                 address=None, phone_numbers=None, email=None, comments=None):
        self.type = type
        self.ref = ref
        self.title = title
        self.first_name = first_name
        self.surname = surname
        self.company = company
        self.address = address
        self.phone_numbers = phone_numbers
        self.email = email
        self.comments = comments

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('payer')

        if self.type is not None:
            element.set('type', self.type)

        if self.ref is not None:
            element.set('ref', self.ref)

        if self.title is not None:
            SubElement(element, 'title').text = self.title

        if self.first_name is not None:
            SubElement(element, 'firstname').text = self.first_name

        if self.surname is not None:
            SubElement(element, 'surname').text = self.surname

        if self.company is not None:
            SubElement(element, 'company').text = self.company

        if self.address is not None:
            element.append(self.address.to_xml_element())

        if self.phone_numbers is not None:
            element.append(self.phone_numbers.to_xml_element())

        if self.email is not None:
            SubElement(element, 'email').text = self.email

        if self.comments:
            element = SubElement(element, 'comments')
            for comment in self.comments:
                element.append(comment.to_xml_element())

        return element


class PayerAddress(object):
    """
    Domain object representing Payer address to be passed to Realex.
    :params str line1: The address line 1.
    :params str line2: The address line 2.
    :params str line3: The address line 3.
    :params str city: The address city.
    :params str county: The address country.
    :params str postcode: The address postcode.
    :params Country country: The address country.
    """
    def __init__(self, line1=None, line2=None, line3=None, city=None, county=None, postcode=None, country=None):
        self.line1 = line1
        self.line2 = line2
        self.line3 = line3
        self.city = city
        self.county = county
        self.postcode = postcode
        self.country = country

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('payeraddress')

        if self.line1 is not None:
            SubElement(element, 'line1').text = self.line1

        if self.line2 is not None:
            SubElement(element, 'line2').text = self.line2

        if self.line3 is not None:
            SubElement(element, 'line3').text = self.line3

        if self.city is not None:
            SubElement(element, 'city').text = self.city

        if self.county is not None:
            SubElement(element, 'county').text = self.county

        if self.postcode is not None:
            SubElement(element, 'postcode').text = self.postcode

        if self.country is not None:
            element.append(self.country.to_xml_element())

        return element


class PhoneNumbers(object):
    """
    Domain object representing Payer phone numbers information to be passed to Realex.

    :param str home_phone_number: The home phone number.
    :param str work_phone_number: The work phone number.
    :param str fax_phone_number: The fax phone number.
    :param str mobile_phone_number: The mobile phone number.
    """
    def __init__(self, home_phone_number=None, work_phone_number=None, fax_phone_number=None, mobile_phone_number=None):
        self.home_phone_number = home_phone_number
        self.work_phone_number = work_phone_number
        self.fax_phone_number = fax_phone_number
        self.mobile_phone_number = mobile_phone_number

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('phonenumbers')

        if self.home_phone_number is not None:
            SubElement(element, 'home').text = self.home_phone_number

        if self.work_phone_number is not None:
            SubElement(element, 'work').text = self.work_phone_number

        if self.fax_phone_number is not None:
            SubElement(element, 'fax').text = self.fax_phone_number

        if self.mobile_phone_number is not None:
            SubElement(element, 'mobile').text = self.mobile_phone_number

        return element


class Recurring(object):
    """
    If you are configured for recurring/continuous authority transactions, you must set the recurring values.

    :param str type: Type can be either fixed or variable depending on whether you will be changing the amounts or not.
    :param str sequence: The recurring sequence. Must be first for the first transaction for this card,
        subsequent for transactions after that, and last for the final transaction of the set.
        Only supported by some acquirers.
    :param str flag: The recurring flag. Optional field taking values 0, 1 or 2.
    """
    def __init__(self, type=None, sequence=None, flag=None):
        self.type = type
        self.sequence = sequence
        self.flag = flag

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('recurring')

        if self.type is not None:
            element.set('type', self.type)

        if self.sequence is not None:
            element.set('sequence', self.sequence)

        if self.flag is not None:
            element.set('flag', self.flag)

        return element


class RecurringType(object):
    """
    Enumeration representing the recurring type.
    """
    none = ''
    variable = 'variable'
    fixed = 'fixed'


class RecurringSequence(object):
    """
    Enumeration representing the recurring sequence. Must be first for the first transaction for this card,
    subsequent for transactions after that, and last for the final transaction of the set.
    Only supported by some acquirers.
    """
    none = ''
    first = 'first'
    subsequent = 'subsequent'
    last = 'last'


class RecurringFlag(object):
    """
    Enumeration representing the recurring flag.
    """
    none = ''
    zero = '0'
    one = '1'
    two = '2'


class TssInfo(object):
    """
    Domain object representing TSS (realscore) information to be passed to Realex.
    Realscore is a real time transaction screening and data checking system to assist a merchant
    with the identification of potentially high-risk transactions.

    :param str customer_number: The number you assign to the customer.
        This can allow checking of previous transactions by this customer.
    :param str product_id: The product code you assign to the product.
    :param str variable_reference: Any reference you also would like to assign to the customer.
        This can allow checking, using realscore, of previous transactions by this customer.
    :param str customer_ip_address: The IP address of the customer.
    :param addresses: The addresses of the customer.
    :type: list of Address
    """
    def __init__(self, customer_number=None, product_id=None, variable_reference=None,
                 customer_ip_address=None, addresses=None):
        self.customer_number = customer_number
        self.product_id = product_id
        self.variable_reference = variable_reference
        self.customer_ip_address = customer_ip_address
        self.addresses = addresses

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('tssinfo')

        if self.customer_number is not None:
            SubElement(element, 'custnum').text = self.customer_number

        if self.product_id is not None:
            SubElement(element, 'prodid').text = self.product_id

        if self.variable_reference is not None:
            SubElement(element, 'varref').text = self.variable_reference

        if self.customer_ip_address is not None:
            SubElement(element, 'custipaddress').text = self.customer_ip_address

        if self.addresses:
            for address in self.addresses:
                element.append(address.to_xml_element())

        return element


class TssResult(object):
    """
    The results of realscore checks.

    :param str result: The weighted total score of realscore.
        The weights can be adjusted in the realcontrol application.
    :param checks: The list of realscore check results.
    :type: list of TssResultCheck
    """
    def __init__(self, result=None, checks=None):
        self.result = result
        self.checks = checks

    @staticmethod
    def from_xml_element(element):
        """
        Load the current instance with the given XML `Element` object.
        :param Element element: The XML element.
        """
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
    """
    Domain object representing the results of an individual realscore check.

    :param str id: The ID of the realscore check.
    :param str value: The value of the realscore check.
    """
    def __init__(self, id=None, value=None):
        self.id = id
        self.value = value

    @staticmethod
    def from_xml_element(element):
        """
        Load the current instance with the given XML `Element` object.
        :param Element element: The XML element.
        """
        check = TssResultCheck()

        if 'id' in element.attrib:
            check.id = element.attrib['id']

        check.value = element.text

        return check


class Request(object):
    """
    Base class to be implemented by all classes which represent Realex requests.
    """
    def generate_defaults(self, secret):
        """
        Generate default values for fields such as hash, timestamp and order ID.
        :param str secret:
        """
        raise NotImplementedError()

    def response_from_xml(self, xml):
        """
        Return a concrete implementation of the response class from an XML source.
        :param str xml: The XML to be parsed.
        :return:
        """
        raise NotImplementedError()

    def to_xml(self):
        """
        Return an XML representation of the interface implementation.
        :return str: The XML representation.
        """
        raise NotImplementedError()


class Response(object):
    """
    Base class to be implemented by all classes which represent Realex responses.
    """

    def is_hash_valid(self, secret):
        """
        Validates the hash in the response is correct.
        :param str secret:
        :return bool: `True` if valid, `False` if not.
        """
        raise NotImplementedError()


class PaymentType(object):
    """
    Enumeration for the payment type.
    """
    auth = 'auth'
    auth_mobile = 'auth-mobile'
    settle = 'settle'
    void = 'void'
    rebate = 'rebate'
    otb = 'otb'
    credit = 'credit'
    hold = 'hold'
    release = 'release'
    receipt_in = 'receipt-in'
    payment_out = 'payment-out'
    payer_new = 'payer-new'
    payer_edit = 'payer-edit'
    card_new = 'card-new'
    card_update = 'card-update-card'
    card_cancel = 'card-cancel-card'
    dcc_rate_lookup = 'dccrate'
    receipt_in_otb = 'receipt-in-otb'
    stored_card_dcc_rate = 'realvault-dccrate'


class PaymentRequest(Request):
    """
    Class representing a Payment request to be sent to Realex.

    :param str timestamp: Format of timestamp is yyyyMMddhhmmss  e.g. 20150131094559 for 31/01/2015 09:45:59.
        If the timestamp is more than a day (86400 seconds) away from the server time,
        then the request is rejected.
    :param str type: The payment type.
    :param str merchant_id: Represents Realex Payments assigned merchant id.
    :param str account: Represents the Realex Payments subaccount to use.
        If this element is omitted, then the default account is used.
    :param str channel: For certain acquirers it is possible to specify whether a transaction is to be processed
        as a Mail Order/Telephone Order or Ecommerce transaction.
        For other banks, this is configured on the Merchant ID level.
    :param str order_id: Represents the unique order id of this transaction.
        Must be unique across all of the sub-accounts.
    :param Amount amount: The `Amount` object containing the amount value and the currency type.
    :param Card card: The `card` object containing the card details to be passed in request.
    :param AutoSettle auto_settle: The `AutoSettle` object containing the auto settle flag.
    :param comments: List of `Comment` objects to be passed in request.
        Optionally, up to two comments can be associated with any transaction.
    :type: list of Comment
    :param str payments_reference: Represents the Realex Payments reference of the original transaction
        (this is included in the response to the auth).
    :param str auth_code: Represents the authcode of the original transaction, which was included in the response.
    :param str mobile: The mobile auth payment type e.g. apple-pay.
    :param str token: The mobile auth payment token to be sent in place of payment data.
    :param Mpi mpi: Contains 3D Secure/Secure Code information if this transaction has used
        a 3D Secure/Secure Code system, either Realex's RealMPI or a third party's.
    :param Payer payer: The payer information to be used on Card Storage transactions.
    :param str payer_ref: The payer ref for this customer.
    :param PaymentData payment_data: The payment information to be used on Receipt-in transactions.
    :param str payment_method: The payment reference.
    :param str fraud_filter: Fraud filter flag
    :param Recurring recurring: If you are configured for recurring/continuous authority transactions,
        you must set the recurring values.
    :param TssInfo tss_info: TSS Info contains optional variables which can be used to identify
        customers in the Realex Payments system.
    :param str refund_hash: Represents a hash of the refund password, which Realex Payments will provide.
        The SHA1 algorithm must be used to generate this hash.
    :param str sha1_hash: Hash constructed from the time stamp, merchand ID, order ID, amount, currency,
        card number and secret values.
    """
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
        self.payments_reference = kwargs.get('payments_reference')
        self.auth_code = kwargs.get('auth_code')
        self.mobile = kwargs.get('mobile')
        self.token = kwargs.get('token')
        self.mpi = kwargs.get('mpi')
        self.payer = kwargs.get('payer')
        self.payer_ref = kwargs.get('payer_ref')
        self.payment_data = kwargs.get('payment_data')
        self.payment_method = kwargs.get('payment_method')
        self.fraud_filter = kwargs.get('fraud_filter')
        self.recurring = kwargs.get('recurring')
        self.tss_info = kwargs.get('tss_info')
        self.refund_hash = kwargs.get('refund_hash')
        self.sha1_hash = kwargs.get('sha1_hash')

    def generate_defaults(self, secret):
        """
        Generate default values for fields such as hash, timestamp and order ID.
        :param str secret:
        """
        if self.timestamp is None:
            self.timestamp = GenerationUtils.generate_timestamp()

        if self.order_id is None:
            self.order_id = GenerationUtils.generate_order_id()

        if self.sha1_hash is None:
            self.generate_hash(secret)

    def generate_hash(self, secret):
        """
        Create the security hash from a number of fields and the shared secret.
        :param str secret:
        """
        timestamp = self.timestamp or ''
        merchant_id = self.merchant_id or ''
        order_id = self.order_id or ''
        token = self.token or ''
        payer_ref = self.payer_ref

        payer_new_ref = ''
        if self.payer and self.payer.ref:
            payer_new_ref = self.payer.ref

        amount = ''
        if self.amount and self.amount.amount:
            amount = self.amount.amount

        currency = ''
        if self.currency and self.amount.currency:
            currency = self.amount.currency

        card_ref = ''
        if self.card and self.card.ref:
            card_ref = self.card.ref

        card_number = ''
        if self.card and self.card.number:
            card_number = self.card.number

        card_payer_ref = ''
        if self.card and self.card.payer_ref:
            card_payer_ref = self.card.payer_ref

        card_holder_name = ''
        if self.card and self.card.card_holder_name:
            card_holder_name = self.card.card_holder_name

        card_expiry_date = ''
        if self.card and self.card.expiry_date:
            card_expiry_date = self.card.expiry_date

        if self.type == PaymentType.auth_mobile:
            to_hash = '.'.join((timestamp, merchant_id, order_id, amount, currency, token))
        elif self.type == PaymentType.otb:
            to_hash = '.'.join((timestamp, merchant_id, order_id, card_number))
        elif self.type == PaymentType.receipt_in:
            to_hash = '.'.join((timestamp, merchant_id, order_id, amount, currency, payer_ref))
        elif self.type == PaymentType.payer_new:
            to_hash = '.'.join((timestamp, merchant_id, order_id, amount, currency, payer_new_ref))
        elif self.type == PaymentType.card_new:
            to_hash = '.'.join(
                (timestamp, merchant_id, order_id, amount, currency, card_payer_ref, card_holder_name, card_number))
        elif self.type == PaymentType.card_update:
            to_hash = '.'.join(
                (timestamp, merchant_id, card_payer_ref, card_ref, card_expiry_date, card_number))
        elif self.type == PaymentType.card_cancel:
            to_hash = '.'.join((timestamp, merchant_id, card_payer_ref, card_ref))
        elif self.type == PaymentType.receipt_in_otb:
            to_hash = '.'.join((timestamp, merchant_id, order_id, payer_ref))
        elif self.type == PaymentType.stored_card_dcc_rate:
            to_hash = '.'.join((timestamp, merchant_id, order_id, amount, currency, payer_ref))
        else:
            to_hash = '.'.join((timestamp, merchant_id, order_id, amount, currency, card_number))

        self.sha1_hash = GenerationUtils.generate_hash(to_hash, secret)

    def response_from_xml(self, xml):
        """
        Return a concrete implementation of the response class from an XML source.
        :param str xml: The xml to be parsed.
        :return PaymentResponse: A instance of `PaymentResponse`.
        """
        return PaymentResponse.from_xml(xml)

    def to_xml(self):
        """
        Return an XML representation of the interface implementation.
        :return str: The XML representation.
        """
        root = Element('request', timestamp=self.timestamp, type=self.type)

        if self.merchant_id is not None:
            SubElement(root, 'merchantid').text = self.merchant_id

        if self.channel is not None:
            SubElement(root, 'channel').text = self.channel

        if self.order_id is not None:
            SubElement(root, 'orderid').text = self.order_id

        if self.amount is not None:
            root.append(self.amount.to_xml_element())

        if self.card is not None:
            root.append(self.card.to_xml_element())

        if self.auto_settle is not None:
            root.append(self.auto_settle.to_xml_element())

        if self.comments:
            element = SubElement(root, 'comments')
            for comment in self.comments:
                element.append(comment.to_xml_element())

        if self.auth_code is not None:
            SubElement(root, 'authcode').text = self.auth_code

        if self.payments_reference is not None:
            SubElement(root, 'pasref').text = self.payments_reference

        if self.mobile is not None:
            SubElement(root, 'mobile').text = self.mobile

        if self.token is not None:
            SubElement(root, 'token').text = self.token

        if self.mpi is not None:
            root.append(self.mpi.to_xml_element())

        if self.payer is not None:
            root.append(self.payer.to_xml_element())

        if self.payer_ref is not None:
            SubElement(root, 'payerref').text = self.payer_ref

        if self.payment_data is not None:
            root.append(self.payment_data.to_xml_element())

        if self.payment_method is not None:
            SubElement(root, 'paymentmethod').text = self.payment_method

        if self.fraud_filter is not None:
            SubElement(root, 'fraudfilter').text = self.fraud_filter

        if self.recurring is not None:
            root.append(self.recurring.to_xml_element())

        if self.tss_info is not None:
            root.append(self.tss_info.to_xml_element())

        if self.refund_hash is not None:
            SubElement(root, 'refundhash').text = self.refund_hash

        if self.sha1_hash is not None:
            SubElement(root, 'sha1hash').text = self.sha1_hash

        return tostring(root)


class PaymentResponse(Response):
    """
    Class representing a Payment response received from Realex.

    :param str timestamp: Time stamp in the format YYYYMMDDHHMMSS, which represents the time in the format year
        month date hour minute second.
    :param str merchant_id: Represents Realex Payments assigned merchant id.
    :param str account: Represents the Realex Payments subaccount to use. If you omit this element then
        we will use your default account.
    :param str order_id: Represents the unique order id of this transaction.
        Must be unique across all of your accounts.
    :param str result: The result codes returned by the Realex Payments system.
    :param str auth_code: If successful an authcode is returned from the bank.
        Used when referencing this transaction in refund and void requests.
    :param str message: The text of the response.
    :param str payments_reference: The Realex payments reference (pasref) for the transaction.
        Used when referencing this transaction in refund and void requests.
    :param str cvn_result: The result of the Card Verification check.
    :param str time_taken: The time taken.
    :param str auth_time_taken: The AUTH time taken.
    :param str acquirer_response: The raw XML response from the acquirer (if the account is set up to return this).
    :param str batch_id: The batch id of the transaction. Returned in the case of auth and refund requests.
        This can be used to assist with the reconciliation of your batches.
    :param CardIssuer card_issuer: The raw XML response from the acquirer (if the account is set up to return this).
    :param TssResult tss_result: The results of realscore.
    :param str avs_postcode_response: Contains postcode match result from Address Verification Service.
    :param str avs_address_response: Contains address match result from Address Verification Service.
    :param str sha1_hash: The SHA-1 hash of certain elements of the response.
        The details of this are to be found in the realauth developer's guide.
    """
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get('timestamp')
        self.merchant_id = kwargs.get('merchant_id')
        self.account = kwargs.get('account')
        self.order_id = kwargs.get('order_id')
        self.result = kwargs.get('result')
        self.auth_code = kwargs.get('auth_code')
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
        self.sha1_hash = kwargs.get('sha1_hash')

    @staticmethod
    def from_xml(xml):
        """
        Unmarshals the passed XML to a `PaymentResponse` object.
        :param xml: The XML to be be parsed.
        :return: A instance of `PaymentResponse`
        """
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
            response.sha1_hash = element.text

        return response

    def is_hash_valid(self, secret):
        """
        Validates the hash in the response is correct.
        :param str secret:
        :return bool: `True` if valid, `False` if not.
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
        return expected_hash == self.sha1_hash


class PaymentData(object):
    """
    Domain object representing PaymentData information to be passed to Realex Card Storage
    for Receipt-in transactions.
    Payment data contains the CVN number for the stored card.

    :param CvnNumber cvn_number: A container for the CVN number.
    """
    def __init__(self, cvn_number=None):
        self.cvn_number = cvn_number

    def to_xml_element(self):
        """
        Return an XML element of the current state of the class.
        :return Element: An XML element.
        """
        element = Element('paymentdata')

        if self.cvn_number is not None:
            element.append(self.cvn_number.to_xml_element())

        return element


class ThreeDSecure(object):
    """
    Domain object representing 3D Secure (realmpi) information passed back from Realex.
    Realmpi is a real time card holder verification system to assist a merchant with the
    identification of potentially fraudulent transactions.

    :param str status: The outcome of the authentication, required for the authorisation request.
    :param str eci: The e-commerce indicator, required for the authorisation request.
    :param str xid: The XID field, required for the authorisation request.
    :param str cavv: The CAVV or UCAF, required for the authorisation request.
    :param str algorithm: The alogirthm, required for the authorisation request.
    """
    def __init__(self, status=None, eci=None, xid=None, cavv=None, algorithm=None):
        self.status = status
        self.eci = eci
        self.xid = xid
        self.cavv = cavv
        self.algorithm = algorithm

    @staticmethod
    def from_xml_element(element):
        """
        Load the current instance with the given XML `Element` object.
        :param Element element: The XML element.
        """
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
    """
    Enumeration for the ThreeDSecure type.
    """
    verify_enrolled = '3ds-verifyenrolled'
    verify_sig = '3ds-verifysig'
    verify_stored_card_enrolled = 'realvault-3ds-verifyenrolled'


class ThreeDSecureRequest(Request):
    """
    Class representing a 3DSecure request to be sent to Realex.

    :param str timestamp: Format of timestamp is yyyyMMddhhmmss  e.g. 20150131094559 for 31/01/2015 09:45:59.
        If the timestamp is more than a day (86400 seconds) away from the server time, then the request is rejected.
    :param str type: The ThreeDSecure type.
    :param str merchant_id: Represents Realex Payments assigned merchant id.
    :param str account: Represents the Realex Payments subaccount to use.
        If this element is omitted, then the default account is used.
    :param str order_id: Represents the unique order id of this transaction.
        Must be unique across all of the sub-accounts.
    :param Amount amount: The `Amount` object containing the amount value and the currency type.
    :param Card card: The `Card` object containing the card details to be passed in request.
    :param str pares: The pre-encoded PaRes that you obtain from the Issuer's ACS.
    :param comments: List of `Comment` objects to be passed in request.
        Optionally, up to two comments can be associated with any transaction.
    :type: list of Comment
    :param str sha1_hash: Hash constructed from the time stamp, merchand ID, order ID, amount, currency,
        card number and secret values.
    """
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get('timestamp')
        self.type = kwargs.get('type')
        self.merchant_id = kwargs.get('merchant_id')
        self.account = kwargs.get('account')
        self.order_id = kwargs.get('order_id')
        self.amount = kwargs.get('amount')
        self.card = kwargs.get('card')
        self.pares = kwargs.get('pares')
        self.comments = kwargs.get('comments')
        self.sha1_hash = kwargs.get('sha1_hash')

    def generate_defaults(self, secret):
        """
        Generate default values for fields such as hash, timestamp and order ID.
        :param str secret:
        """
        if self.timestamp is None:
            self.timestamp = GenerationUtils.generate_timestamp()

        if self.order_id is None:
            self.order_id = GenerationUtils.generate_order_id()

        if self.sha1_hash is None:
            self.generate_hash(secret)

    def generate_hash(self, secret):
        """
        Create the security hash from a number of fields and the shared secret.
        :param str secret:
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

        self.sha1_hash = GenerationUtils.generate_hash(to_hash, secret)

    def response_from_xml(self, xml):
        """
        Return a concrete implementation of the response class from an XML source.
        :param str xml: The xml to be parsed.
        :return ThreeDSecureResponse: A instance of `ThreeDSecureResponse`.
        """
        return ThreeDSecureResponse.from_xml(xml)

    def to_xml(self):
        """
        Return an XML representation of the interface implementation.
        :return str: The XML representation.
        """
        root = Element('request', timestamp=self.timestamp, type=self.type)

        if self.merchant_id is not None:
            SubElement(root, 'merchantid').text = self.merchant_id

        if self.account is not None:
            SubElement(root, 'account').text = self.account

        if self.order_id is not None:
            SubElement(root, 'orderid').text = self.order_id

        if self.amount is not None:
            root.append(self.amount.to_xml_element())

        if self.card is not None:
            root.append(self.card.to_xml_element())

        if self.pares is not None:
            SubElement(root, 'pares').text = self.pares

        if self.comments:
            element = SubElement(root, 'comments')
            for comment in self.comments:
                element.append(comment.to_xml_element())

        if self.sha1_hash is not None:
            SubElement(root, 'sha1hash').text = self.sha1_hash

        return tostring(root)


class ThreeDSecureResponse(Response):
    """
    Class representing a 3DSecure response received from Realex.

    :param str timestamp: The time stamp in the format YYYYMMDDHHMMSS,
        which represents the time in the format year month date hour minute second.
    :param str merchant_id: Represents Realex Payments assigned merchant id.
    :param str account: Represents the Realex Payments subaccount to use.
        If you omit this element then we will use your default account.
    :param str order_id: Represents the unique order id of this transaction.
        Must be unique across all of your accounts.
    :param str result: The result codes returned by the Realex Payments system.
    :param str auth_code: If successful an authcode is returned from the bank.
        Used when referencing this transaction in refund and void requests.
    :param str message: The text of the response.
    :param str payments_reference: The Realex payments reference (pasref) for the transaction.
        Used when referencing this transaction in refund and void requests.
    :param str time_taken: The time taken.
    :param str auth_time_taken: The AUTH time taken.
    :param str pareq: The pre-encoded PaReq that you must post to the Issuer's ACS url.
    :param str url: The URL of the Issuer ACS.
    :param str enrolled: The enrolment response from ACS.
    :param str xid: The XID from ACS.
    :param ThreeDSecure threedsecure: The 3D Secure details.
    :param str sha1_hash: The SHA-1 hash of certain elements of the response.
        The details of this are to be found in the realmpi developer's guide.
    """
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
        self.sha1_hash = kwargs.get('sha1_hash')

    @staticmethod
    def from_xml(xml):
        """
        Unmarshal the passed XML to a `ThreeDSecureResponse` object.
        :param xml: The XML to be be parsed.
        :return: A instance of `ThreeDSecureResponse`
        """
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
            response.sha1_hash = element.text

        return response

    def is_hash_valid(self, secret):
        """
        Validate the response from realex. Raises an exception
        if validation fails.
        :param str secret:
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
        return expected_hash == self.sha1_hash
