from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from threading import Lock, Thread
from types import TracebackType
from typing import Generator, List, Optional, Tuple, Type

from server.consts import ServerType
from server.log import print_error, print_success
from server.photon.operation_code import OperationCode
from server.photon.packet.base import PhotonDataPacket
from server.photon.queue.photon_client_socket import PhotonClientSocket


class PhotonQueueDispatcher:
    _clients: List[PhotonClientSocket]
    _client_accepter_worker: Thread
    _server_sock: socket
    _bind_if: str
    _bind_port: int
    _closing: bool
    _clients_lock: Lock

    def __init__(
        self, server_type: ServerType, bind_interface: str, bind_port: int
    ) -> None:
        self._server_sock = socket(AF_INET, SOCK_STREAM)
        self._bind_if = bind_interface
        self._bind_port = bind_port
        self._closing = False

        self._client_accepter_worker = Thread(
            target=self._client_accepter, name="Client Accepter Worker"
        )

        self._clients = []
        self._clients_lock = Lock()
        self._server_type = server_type

    def __enter__(self):
        self._server_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._server_sock.bind((self._bind_if, self._bind_port))
        self._server_sock.listen(5)
        print_success(
            self._server_type, f"Server listening on {self._bind_if}:{self._bind_port}"
        )

        self._client_accepter_worker.start()

        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self._closing = True
        try:
            self._server_sock.close()
        except Exception:
            pass
        self._client_accepter_worker.join(5)

    def _client_accepter(self):
        while not self._closing:
            try:
                sock, addr = self._server_sock.accept()
            except OSError:
                if self._closing:
                    break
                continue
            print_success(
                self._server_type, f"New client connected: {addr[0]}:{addr[1]}"
            )
            with self._clients_lock:
                self._clients.append(
                    PhotonClientSocket(
                        sock=sock, addr=addr, server_type=self._server_type
                    )
                )

    def process(
        self,
        do_not_handle: Optional[Tuple[OperationCode, ...]] = None,
    ) -> Generator[Tuple[PhotonClientSocket, PhotonDataPacket], None, None]:
        with self._clients_lock:
            self._clients = [
                client for client in self._clients if not client.is_disconnected()
            ]
            clients_snapshot = list(self._clients)

        for client in clients_snapshot:
            try:
                for packet_requiring_attention in client.process(
                    do_not_handle=do_not_handle
                ):
                    yield (client, packet_requiring_attention)
            except Exception as ex:
                print_error(
                    self._server_type,
                    f"Client processing failed for {client.get_address()}: {type(ex).__name__}: {ex}",
                )

    def get_clients(self) -> List[PhotonClientSocket]:
        with self._clients_lock:
            return list(self._clients)
