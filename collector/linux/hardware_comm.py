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


def _find_serial(t: Transport) -> list[HardwareInterface]:
    r = t.run("ls /dev/ttyS* /dev/ttyUSB* /dev/ttyAMA* /dev/ttyACM* 2>/dev/null")
    return [
        HardwareInterface(
            type="uart",
            device_path=line.strip(),
            description="Serial/UART device",
            accessible=True,
        )
        for line in r.stdout.strip().splitlines()
        if line.strip()
    ]


def _find_spi(t: Transport) -> list[HardwareInterface]:
    r = t.run("ls /dev/spidev* 2>/dev/null")
    return [
        HardwareInterface(
            type="spi",
            device_path=line.strip(),
            description="SPI device",
            accessible=True,
        )
        for line in r.stdout.strip().splitlines()
        if line.strip()
    ]


def _find_i2c(t: Transport) -> list[HardwareInterface]:
    r = t.run("ls /dev/i2c-* 2>/dev/null")
    return [
        HardwareInterface(
            type="i2c",
            device_path=line.strip(),
            description="I2C bus",
            accessible=True,
        )
        for line in r.stdout.strip().splitlines()
        if line.strip()
    ]


def _find_gpio(t: Transport) -> list[HardwareInterface]:
    r = t.run("ls /sys/class/gpio/gpiochip* 2>/dev/null || ls /dev/gpiochip* 2>/dev/null")
    return [
        HardwareInterface(
            type="gpio",
            device_path=line.strip(),
            description="GPIO controller",
            accessible=True,
        )
        for line in r.stdout.strip().splitlines()
        if line.strip()
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
            accessible=True,
        )
        for line in r.stdout.strip().splitlines()
        if line.strip()
    ]
