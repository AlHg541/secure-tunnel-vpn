"""
TUN Interface Module - Phase 1
Creates and manages a virtual TUN network interface in user space.
"""

import os
import fcntl
import struct
import subprocess
import logging

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TUNInterface:
    """Manages a TUN virtual network interface"""

    def __init__(self, name='tun0', ip_address='10.8.0.2', netmask='255.255.255.0'):
        self.name = name
        self.ip_address = ip_address
        self.netmask = netmask
        self.fd = None

    def create(self):
        """Create and configure the TUN interface"""
        try:
            self.fd = os.open('/dev/net/tun', os.O_RDWR)

            ifr = struct.pack('16sHH', self.name.encode(), IFF_TUN | IFF_NO_PI, 0)

            fcntl.ioctl(self.fd, TUNSETIFF, ifr)
            logger.info(f"Created TUN interface: {self.name}")

            self._configure_interface()

            return self.fd

        except Exception as e:
            logger.error(f"Failed to create TUN interface: {e}")
            if self.fd:
                os.close(self.fd)
            raise

    def _configure_interface(self):
        """Configure IP address and bring interface up"""
        try:
            cmd_ip = f"sudo ip addr add {self.ip_address}/24 dev {self.name}"
            subprocess.run(cmd_ip.split(), check=True, capture_output=True)
            logger.info(f"Assigned IP {self.ip_address} to {self.name}")

            cmd_up = f"sudo ip link set {self.name} up"
            subprocess.run(cmd_up.split(), check=True, capture_output=True)
            logger.info(f"Brought up interface {self.name}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure interface: {e}")
            raise

    def read_packet(self):
        """Read a raw IP packet from the TUN interface"""
        if not self.fd:
            raise RuntimeError("TUN interface not created")

        try:
            packet = os.read(self.fd, 65535)
            logger.debug(f"Read packet: {len(packet)} bytes")
            return packet
        except OSError as e:
            logger.error(f"Error reading from TUN: {e}")
            raise

    def write_packet(self, packet):
        """Write a raw IP packet to the TUN interface"""
        if not self.fd:
            raise RuntimeError("TUN interface not created")

        try:
            os.write(self.fd, packet)
            logger.debug(f"Wrote packet: {len(packet)} bytes")
        except OSError as e:
            logger.error(f"Error writing to TUN: {e}")
            raise

    def close(self):
        """Close the TUN interface"""
        if self.fd:
            try:
                cmd_down = f"sudo ip link set {self.name} down"
                subprocess.run(cmd_down.split(), check=True, capture_output=True)
                logger.info(f"Brought down interface {self.name}")
            except:
                pass

            os.close(self.fd)
            self.fd = None
            logger.info("TUN interface closed")


def test_tun_interface():
    """Test the TUN interface creation and basic operations"""
    logger.info("Starting TUN interface test...")

    tun = TUNInterface(name='tun0', ip_address='10.8.0.2')

    try:
        tun.create()

        result = subprocess.run(['ip', 'addr', 'show', 'tun0'],
                              capture_output=True, text=True)
        print("\n=== Interface Status ===")
        print(result.stdout)

        print("\n=== Test Successful ===")
        print(f"✓ TUN interface 'tun0' created")
        print(f"✓ IP address assigned: 10.8.0.2/24")
        print(f"✓ Interface is UP and ready")
        print("\nPress Ctrl+C to stop and cleanup...")

        import time
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
    except Exception as e:
        logger.error(f"Test failed: {e}")
    finally:
        tun.close()


if __name__ == '__main__':
    test_tun_interface()