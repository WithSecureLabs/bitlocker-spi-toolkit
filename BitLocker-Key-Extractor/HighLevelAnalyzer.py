"""This module implements BitLocker key extractor analyzer for Saleae Logic 2

Installation:
Add the analyzer by selecting Load Existing Extension from Logic 2's extensions tab.
"""
from enum import Enum
import re
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

OPERATION_MASK = 0x80
ADDRESS_MASK = 0x3f
WAIT_MASK = 0xfe
WAIT_END = 0x01
TPM_DATA_FIFO_0 = 0xd40024

WINDOW_SIZE = 0x2c


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
        address (bytearray): The target address in the transatcion. (little-endian).
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


class Hla(HighLevelAnalyzer):
    """Implements the BitLocker key extractor

    Attributes:
        state (TransactionState): The current state of the state machine
        current_transaction (Transaction): Contains the transaction to be decoded
        window (bytearray): the last WINDOW_SIZE bytes from transactions. Used to search the key
    """
    result_types = {}

    state = TransactionState.READ_OPERATION
    current_transaction = None
    window = b''

    def __init__(self):
        pass

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'enable':
            self._reset_state_machine()
        elif frame.type == 'disable':
            self._reset_state_machine()
        elif frame.type == 'result':
            mosi = frame.data['mosi'][0]
            miso = frame.data['miso'][0]
            self._state_machine(mosi, miso, frame)

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
            self._append_transaction()
            key = self._find_key()
            if key:
                print(f'[+] Found BitLocker key: {key}')
                self.window = b''
            if len(self.window) >= WINDOW_SIZE:
                self.window = self.window[-WINDOW_SIZE:]

    def _append_transaction(self):
        if int.from_bytes(self.current_transaction.address, "big") != TPM_DATA_FIFO_0:
            return
        self.window += self.current_transaction.data

    def _find_key(self):
        data = self.window.hex()
        key = re.findall(
            r'2c00000001000[0-1]000[0-5]200000(\w{64})', data)
        if key:
            return key[0]
        return None
