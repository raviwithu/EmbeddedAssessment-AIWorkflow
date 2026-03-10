"""Enumerate hardware communication interfaces on a Linux target.

Checks for UART/serial, SPI, I2C, GPIO, and USB devices.
All operations are read-only.
"""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import HardwareInterface

logger = logging.getLogger(__name__)


def collect_hardware_interfaces(transport: Transport) -> list[HardwareInterface]:
    """Discover available hardware communication interfaces."""
    interfaces: list[HardwareInterface] = []
    interfaces.extend(_find_serial(transport))
    interfaces.extend(_find_spi(transport))
    interfaces.extend(_find_i2c(transport))
    interfaces.extend(_find_gpio(transport))
    interfaces.extend(_find_usb(transport))
    return interfaces


def _check_readable(t: Transport, paths: list[str]) -> set[str]:
    """Return the subset of *paths* that the current user can read."""
    if not paths:
        return set()
    tests = " && ".join(f'test -r "{p}" && echo "{p}"' for p in paths)
    r = t.run(f"{{ {tests}; }} 2>/dev/null; true")
    return {line.strip() for line in r.stdout.strip().splitlines() if line.strip()}


def _find_dev_interfaces(
    t: Transport, glob: str, iface_type: str, description: str
) -> list[HardwareInterface]:
    """Generic helper: list device files matching *glob* and check readability."""
    r = t.run(f"ls {glob} 2>/dev/null")
    paths = [line.strip() for line in r.stdout.strip().splitlines() if line.strip()]
    readable = _check_readable(t, paths)
    return [
        HardwareInterface(
            type=iface_type,
            device_path=p,
            description=description,
            accessible=p in readable,
        )
        for p in paths
    ]


def _find_serial(t: Transport) -> list[HardwareInterface]:
    return _find_dev_interfaces(
        t, "/dev/ttyS* /dev/ttyUSB* /dev/ttyAMA* /dev/ttyACM*", "uart", "Serial/UART device"
    )


def _find_spi(t: Transport) -> list[HardwareInterface]:
    return _find_dev_interfaces(t, "/dev/spidev*", "spi", "SPI device")


def _find_i2c(t: Transport) -> list[HardwareInterface]:
    return _find_dev_interfaces(t, "/dev/i2c-*", "i2c", "I2C bus")


def _find_gpio(t: Transport) -> list[HardwareInterface]:
    r = t.run("ls /sys/class/gpio/gpiochip* /dev/gpiochip* 2>/dev/null")
    paths = [line.strip() for line in r.stdout.strip().splitlines() if line.strip()]
    readable = _check_readable(t, paths)
    return [
        HardwareInterface(
            type="gpio",
            device_path=p,
            description="GPIO controller",
            accessible=p in readable,
        )
        for p in paths
    ]


def _find_usb(t: Transport) -> list[HardwareInterface]:
    r = t.run("lsusb 2>/dev/null")
    if r.exit_code != 0:
        return []
    return [
        HardwareInterface(
            type="usb",
            device_path="",
            description=line.strip(),
            accessible=True,  # lsusb only lists devices that are accessible
        )
        for line in r.stdout.strip().splitlines()
        if line.strip()
    ]
