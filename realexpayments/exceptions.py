class RealexError(Exception):
    pass


class RealexServerError(Exception):
    def __init__(self, timestamp, order_id, result, message):
        self.timestamp = timestamp
        self.order_id = order_id
        self.result = result
        self.message = message
