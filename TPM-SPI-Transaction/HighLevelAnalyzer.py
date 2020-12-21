"""Implements TPM SPI transaction decoder for Logic 2"""
from enum import Enum
from saleae.analyzers import (
    HighLevelAnalyzer,
    AnalyzerFrame,
    StringSetting,
    ChoicesSetting
)
from registry import fifo

OPERATION_MASK = 0x80
ADDRESS_MASK = 0x3f
WAIT_MASK = 0xfe
WAIT_END = 0x01


class Operation(Enum):
    """Enum for a TPM transaction type"""
    READ = 0x80
    WRITE = 0x00


class TransactionState(Enum):
    """Different states for the decofing state machine"""
    READ_OPERATION = 1
    READ_ADDRESS = 2
    WAIT = 3
    TRANSFER_BYTE = 4


class Transaction:
    """Capsulates one TPM SPI transaction

    Args:
        start_time: A timestamp when the first byte in this transatcion captured.
        operation: Transaction type.
        size: The number of data bytes.

    Attributes:
        start_time: A timestamp when the first byte in this transatcion captured.
        end_time: A timestamp when the last byte in this transatcion captured.
        operation (Operation): Transaction type.
        address (bytearray): The target address in the transatcion. (big-endian).
        data (bytearray): The data in the transatcion.
        size (int): The number of data bytes.
        wait_count (int): Holds the number of wait states between the address and data .
    """
    start_time: float
    end_time: float
    operation: Operation
    address: bytearray
    data: bytearray
    size: int
    wait_count: int

    def __init__(self, start_time, operation, size):
        self.start_time = start_time
        self.end_time = None
        self.operation = operation
        self.address = bytearray()
        self.data = bytearray()
        self.size = size
        self.wait_count = 0

    def is_complete(self):
        """Return True if this transaction is complete.
        A transaction is complete when all address and data bytes are capture"""
        return self.is_address_complete() and self.is_data_complete()

    def is_data_complete(self):
        """Return True if all data bytes are captured."""
        return len(self.data) == self.size

    def is_address_complete(self):
        """Return True if all three address bytes are captured."""
        return len(self.address) == 3

    def frame(self):
        """Return AnalyzerFrame if the transaction is complete"""
        if self.is_complete():
            frame_type = 'read' if self.operation == Operation.READ else 'write'
            register_name = ""
            try:
                register_name = fifo[int.from_bytes(
                    self.address, "big") & 0xffff]
            except KeyError:
                register_name = "Unknown"
            return AnalyzerFrame(frame_type, self.start_time, self.end_time, {
                'register': register_name,
                'addr': "%04x" % int.from_bytes(self.address, "big"),
                'data': self.data.hex(),
                'waits': self.wait_count,
            })
        return None


class Hla(HighLevelAnalyzer):
    """Implements the TPM Transaction decoder.

    Attributes:
        state (TransactionState): The current state of the state machine
        current_transaction (Transaction): Contains the transaction to be decoded
    """
    addr_filter_setting = StringSetting(
        label='Address filter list (hex, comma separated)')
    operation_setting = ChoicesSetting(
        ['Read', 'Write', 'Both'],
        label='Operation selector')

    addr_filters = None
    result_types = {
        'read': {
            'format': 'Rd: {{data.register}}, Data: {{data.data}}'
        },
        'write': {
            'format': 'Wr: {{data.register}}, Data: {{data.data}}'
        }
    }

    state = TransactionState.READ_OPERATION
    current_transaction = None

    def __init__(self):
        if self.addr_filter_setting != "":
            self.addr_filters = list(
                map(lambda x: x.lower(), self.addr_filter_setting.split(',')))

    def decode(self, frame: AnalyzerFrame):
        out_frame = None
        if frame.type == 'enable':
            self._reset_state_machine()
        elif frame.type == 'disable':
            self._reset_state_machine()
        elif frame.type == 'result':
            mosi = frame.data['mosi'][0]
            miso = frame.data['miso'][0]
            out_frame = self._state_machine(mosi, miso, frame)
        return out_frame

    def _reset_state_machine(self):
        self.state = TransactionState.READ_OPERATION

    def _state_machine(self, mosi, miso, frame):
        machine = {
            TransactionState.READ_OPERATION: self._read_state,
            TransactionState.READ_ADDRESS: self._read_address_state,
            TransactionState.WAIT: self._wait_state,
            TransactionState.TRANSFER_BYTE: self._transfer_byte_state
        }
        return machine[self.state](mosi, miso, frame)

    def _read_state(self, mosi, miso, frame):
        operation = Operation(mosi & OPERATION_MASK)
        size_of_transfer = (mosi & ADDRESS_MASK) + 1
        self.current_transaction = Transaction(
            frame.start_time, operation, size_of_transfer)
        self.state = TransactionState.READ_ADDRESS

    def _read_address_state(self, mosi, miso, frame):
        self.current_transaction.address += mosi.to_bytes(1, byteorder='big')
        address_complete = self.current_transaction.is_address_complete()
        if address_complete and miso == WAIT_MASK:
            self.state = TransactionState.WAIT
        elif address_complete:
            self.state = TransactionState.TRANSFER_BYTE

    def _wait_state(self, mosi, miso, frame):
        self.current_transaction.wait_count += 1
        if miso == WAIT_END:
            self.state = TransactionState.TRANSFER_BYTE

    def _transfer_byte_state(self, mosi, miso, frame):
        if self.current_transaction.operation == Operation.READ:
            self.current_transaction.data += miso.to_bytes(1, byteorder='big')
        elif self.current_transaction.operation == Operation.WRITE:
            self.current_transaction.data += mosi.to_bytes(1, byteorder='big')

        if self.current_transaction.is_complete():
            self.current_transaction.end_time = frame.end_time
            self._reset_state_machine()
            return self._build_frame()
        return None

    def _build_frame(self):
        if self.addr_filters and self.current_transaction.address.hex() not in self.addr_filters:
            return None
        if self.operation_setting == 'Read' and self.current_transaction.operation != Operation.READ:
            return None
        if self.operation_setting == 'Write' and self.current_transaction.operation != Operation.WRITE:
            return None
        print(self.current_transaction.data.hex(), end='')
        return self.current_transaction.frame()
