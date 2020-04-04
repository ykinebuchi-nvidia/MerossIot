from abc import ABC, abstractmethod
from threading import RLock
from typing import Optional

from meross_iot.cloud.constants import *
from meross_iot.cloud.exceptions.OfflineDeviceException import OfflineDeviceException
from meross_iot.cloud.timeouts import LONG_TIMEOUT, SHORT_TIMEOUT
from meross_iot.logger import DEVICE_LOGGER as l
from meross_iot.meross_event import DeviceOnlineStatusEvent, DeviceBindEvent, DeviceUnbindEvent


class AbstractMerossDevice(ABC):
    # TODO: typing for the following
    def __init__(self, connection_manager, **kwargs):
        # The following property, holds the raw_status data about this device.
        # TODO: check if we really need this
        self._raw_state = {}
        self._state_lock = RLock()

        # Get device UUID
        if "uuid" not in kwargs:
            raise Exception("No UUID was found for this device")
        self._device_uuid = kwargs['uuid']

        # Information about device
        if "devName" in kwargs:
            self._device_name = kwargs['devName']
        if "deviceType" in kwargs:
            self._device_type = kwargs['deviceType']
        if "fmwareVersion" in kwargs:
            self._device_firmware_version = kwargs['fmwareVersion']
        if "hdwareVersion" in kwargs:
            self._device_hardware_version = kwargs['hdwareVersion']
        if "onlineStatus" in kwargs:
            self._device_online_status = kwargs['onlineStatus']
        if "channels" in kwargs:
            self._channels = kwargs['channels']

    def handle_push_notification(self,
                                 namespace: str,
                                 payload: Optional[dict],
                                 already_handled: bool,
                                 **kwargs) -> bool:
        """
        Handles the push notifications received from the Meross Cloud.

        *Note*: sub-classes that override this method MUST call the `super()`.handle_push_notification() method in
        any case. Then the return value must be True either if the current implementation has handled the event or
        if it has been handled by the parent class. False otherwise.

        *Careful! Python implements boolean shortcuts, so the following snippet should not be used*::

            return handled or super.handle_push_notification()

        Instead, do something like the following::

            parent_handled = super().handle_push_notification
            return handled or parent_handled.

        :param namespace: Event namespace
        :param payload:  Event payload
        :param already_handled: True if the event was already handled by one of the sub-classes, False otherwise
        :return: True if the current implementation or a parent one has handled the event, False otherwise
        """
        if namespace == Namespace.ONLINE:
            # TODO: Do we need to parse the online status or do we keep it as raw?
            self._device_online_status = payload['online']['status']
            # TODO: Fire event?
            return True

        elif namespace == Namespace.BIND:
            data = payload['bind']
            # TODO: Fire event?
            return True

        elif namespace == Namespace.UNBIND:
            # Let everybody know we are going down before doing anything
            evt = DeviceUnbindEvent(device=self)
            # TODO: Fire event?
            # TODO: clear and release resources?
            return True
        elif not already_handled:
            # This is the base-class implementation.
            # If sub-classes did not handle this event, it was unhandled. In this case, we need to
            # log a warning.
            l.warning(f"Unhandled event for namespace {namespace}")
            l.debug(f"Unhandled event for namespace {namespace}, payload {payload}")
            return False

    async def execute_command(self,
                        command_method: CommandMethod,
                        namespace: Namespace,
                        payload: dict,
                        timeout: int = SHORT_TIMEOUT,
                        online_check=True,
                        **kwargs):
        """
        Sends the command to the device.
        When *online_check* is True, this method will first check if the device is online and will only issue the
        command if it is still connected. Issuing a command to an offline device will cause OfflineDeviceException
        to be raised.

        On the contrary, when *online_check* is False, the command is issued to the device regardless of its current
        online status. In this case, if the device results offline, an exception is raised.
        :param command_method: method
        :param namespace: command namespace
        :param payload: command data
        :param timeout: timeout in seconds for the command to execute
        :param online_check: whether to check if the device is online before sending the command.
        :param kwargs:
        :return:
        """
        # If the device is not online, what's the point of issuing the command?
        with self._state_lock:
            if online_check and not self.online:
                raise OfflineDeviceException("The device %s (%s) is offline. The command cannot be executed" %
                                             (self._device_name, self._device_uuid))

            return self.__cloud_client.execute_cmd(uuid=self._device_uuid,
                                                   command=command_method,
                                                   namespace=namespace,
                                                   payload=payload,
                                                   timeout=timeout)
    """
    def get_sys_data(self):
        return self.execute_command("GET", ALL, {}, online_check=False)

    def get_abilities(self):
        # TODO: Make this cached value expire after a bit...
        if self._abilities is None:
            self._abilities = self.execute_command("GET", ABILITY, {})['ability']
        return self._abilities
    """