"""Tests for hardware interface detection (collector/linux/hardware_comm.py)."""

from __future__ import annotations

from collector.linux.hardware_comm import (
    _check_readable,
    _find_gpio,
    _find_i2c,
    _find_serial,
    _find_spi,
    _find_usb,
    collect_hardware_interfaces,
)
from tests.conftest import MockTransport
from tests.linux.conftest import (
    GPIO_DEVICES,
    I2C_DEVICES,
    LSUSB_OUTPUT,
    SERIAL_DEVICES,
    SPI_DEVICES,
)


# ---------------------------------------------------------------------------
# _check_readable
# ---------------------------------------------------------------------------

class TestCheckReadable:
    def test_all_readable(self, mock_transport: MockTransport):
        mock_transport.register_substring("test -r", stdout="/dev/ttyS0\n/dev/ttyS1\n")
        result = _check_readable(mock_transport, ["/dev/ttyS0", "/dev/ttyS1"])
        assert "/dev/ttyS0" in result
        assert "/dev/ttyS1" in result

    def test_none_readable(self, mock_transport: MockTransport):
        mock_transport.register_substring("test -r", stdout="")
        result = _check_readable(mock_transport, ["/dev/ttyS0"])
        assert len(result) == 0

    def test_empty_paths(self, mock_transport: MockTransport):
        result = _check_readable(mock_transport, [])
        assert result == set()


# ---------------------------------------------------------------------------
# Individual finders
# ---------------------------------------------------------------------------

class TestFindSerial:
    def test_finds_serial_devices(self, mock_transport: MockTransport):
        mock_transport.register_substring(
            "ls /dev/ttyS* /dev/ttyUSB* /dev/ttyAMA* /dev/ttyACM*",
            stdout=SERIAL_DEVICES,
        )
        mock_transport.register_substring("test -r", stdout="/dev/ttyS0\n")
        interfaces = _find_serial(mock_transport)
        assert len(interfaces) == 3
        assert all(i.type == "uart" for i in interfaces)
        accessible = [i for i in interfaces if i.accessible]
        assert len(accessible) == 1

    def test_no_serial_devices(self, mock_transport: MockTransport):
        mock_transport.register_substring("ls /dev/ttyS*", stdout="")
        interfaces = _find_serial(mock_transport)
        assert interfaces == []


class TestFindSpi:
    def test_finds_spi_devices(self, mock_transport: MockTransport):
        mock_transport.register_substring("ls /dev/spidev*", stdout=SPI_DEVICES)
        mock_transport.register_substring("test -r", stdout="/dev/spidev0.0\n")
        interfaces = _find_spi(mock_transport)
        assert len(interfaces) == 2
        assert all(i.type == "spi" for i in interfaces)


class TestFindI2c:
    def test_finds_i2c_devices(self, mock_transport: MockTransport):
        mock_transport.register_substring("ls /dev/i2c-*", stdout=I2C_DEVICES)
        mock_transport.register_substring("test -r", stdout="/dev/i2c-0\n/dev/i2c-1\n")
        interfaces = _find_i2c(mock_transport)
        assert len(interfaces) == 2
        assert all(i.type == "i2c" for i in interfaces)
        assert all(i.accessible for i in interfaces)


class TestFindGpio:
    def test_finds_gpio_devices(self, mock_transport: MockTransport):
        mock_transport.register_substring(
            "ls /sys/class/gpio/gpiochip* /dev/gpiochip*",
            stdout=GPIO_DEVICES,
        )
        mock_transport.register_substring("test -r", stdout="/dev/gpiochip0\n")
        interfaces = _find_gpio(mock_transport)
        assert len(interfaces) == 2
        assert all(i.type == "gpio" for i in interfaces)


class TestFindUsb:
    def test_finds_usb_devices(self, mock_transport: MockTransport):
        mock_transport.register("lsusb 2>/dev/null", stdout=LSUSB_OUTPUT)
        interfaces = _find_usb(mock_transport)
        assert len(interfaces) == 2
        assert all(i.type == "usb" for i in interfaces)
        assert all(not i.accessible for i in interfaces)  # lsusb enumerates but doesn't imply access
        assert "root hub" in interfaces[0].description

    def test_lsusb_failure(self, mock_transport: MockTransport):
        mock_transport.register("lsusb 2>/dev/null", exit_code=1)
        assert _find_usb(mock_transport) == []


# ---------------------------------------------------------------------------
# collect_hardware_interfaces (full)
# ---------------------------------------------------------------------------

class TestCollectHardwareInterfaces:
    def test_aggregates_all_types(self, mock_transport: MockTransport):
        mock_transport.register_substring(
            "ls /dev/ttyS* /dev/ttyUSB* /dev/ttyAMA* /dev/ttyACM*",
            stdout="/dev/ttyS0\n",
        )
        mock_transport.register_substring("ls /dev/spidev*", stdout="/dev/spidev0.0\n")
        mock_transport.register_substring("ls /dev/i2c-*", stdout="/dev/i2c-0\n")
        mock_transport.register_substring(
            "ls /sys/class/gpio/gpiochip* /dev/gpiochip*",
            stdout="/dev/gpiochip0\n",
        )
        mock_transport.register("lsusb 2>/dev/null", stdout="Bus 001 Device 001: ID 1d6b:0002 root hub\n")
        mock_transport.register_substring("test -r", stdout="")

        interfaces = collect_hardware_interfaces(mock_transport)
        types = {i.type for i in interfaces}
        assert "uart" in types
        assert "spi" in types
        assert "i2c" in types
        assert "gpio" in types
        assert "usb" in types
