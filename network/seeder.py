"""
SIEM Lite - Demo Device Seeder
Pre-populates the database with realistic demo network devices
and their default thresholds on first run.
"""

import os
import logging
from sqlalchemy.orm import Session
from sqlalchemy import create_engine

from database.models import NetworkDevice, DeviceThreshold, DeviceType, DeviceStatus
from database.connection import create_tables_sync

logger = logging.getLogger(__name__)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem:siempass@localhost:5432/siemdb")

DEMO_DEVICES = [
    {
        "name": "Core Router 01", "ip_address": "192.168.1.1",
        "device_type": DeviceType.ROUTER, "vendor": "Cisco",
        "model": "Cisco ISR 4451", "location": "Server Room A - Rack 1",
        "thresholds": {"temp_warn": 65, "temp_critical": 80,
                       "cpu_warn": 75, "cpu_critical": 90,
                       "bandwidth_warn": 800, "bandwidth_critical": 950},
    },
    {
        "name": "Core Router 02", "ip_address": "192.168.1.2",
        "device_type": DeviceType.ROUTER, "vendor": "Cisco",
        "model": "Cisco ISR 4451", "location": "Server Room A - Rack 2",
        "thresholds": {"temp_warn": 65, "temp_critical": 80,
                       "cpu_warn": 75, "cpu_critical": 90,
                       "bandwidth_warn": 800, "bandwidth_critical": 950},
    },
    {
        "name": "Distribution Switch 01", "ip_address": "192.168.1.10",
        "device_type": DeviceType.SWITCH, "vendor": "Juniper",
        "model": "Juniper EX4300", "location": "Server Room A - Rack 3",
        "thresholds": {"temp_warn": 55, "temp_critical": 70,
                       "cpu_warn": 70, "cpu_critical": 85,
                       "bandwidth_warn": 700, "bandwidth_critical": 900},
    },
    {
        "name": "Distribution Switch 02", "ip_address": "192.168.1.11",
        "device_type": DeviceType.SWITCH, "vendor": "Juniper",
        "model": "Juniper EX4300", "location": "Server Room B - Rack 1",
        "thresholds": {"temp_warn": 55, "temp_critical": 70,
                       "cpu_warn": 70, "cpu_critical": 85,
                       "bandwidth_warn": 700, "bandwidth_critical": 900},
    },
    {
        "name": "Access Switch Floor 1", "ip_address": "192.168.1.20",
        "device_type": DeviceType.SWITCH, "vendor": "HP",
        "model": "HP Aruba 2930F", "location": "Floor 1 - IDF Closet",
        "thresholds": {"temp_warn": 50, "temp_critical": 65,
                       "cpu_warn": 60, "cpu_critical": 80},
    },
    {
        "name": "Access Switch Floor 2", "ip_address": "192.168.1.21",
        "device_type": DeviceType.SWITCH, "vendor": "HP",
        "model": "HP Aruba 2930F", "location": "Floor 2 - IDF Closet",
        "thresholds": {"temp_warn": 50, "temp_critical": 65,
                       "cpu_warn": 60, "cpu_critical": 80},
    },
    {
        "name": "Perimeter Firewall", "ip_address": "10.0.0.1",
        "device_type": DeviceType.FIREWALL, "vendor": "Palo Alto",
        "model": "PA-3220", "location": "DMZ - Rack 1",
        "thresholds": {"temp_warn": 60, "temp_critical": 75,
                       "cpu_warn": 80, "cpu_critical": 95,
                       "bandwidth_warn": 900, "bandwidth_critical": 980},
    },
    {
        "name": "WiFi Controller", "ip_address": "192.168.1.50",
        "device_type": DeviceType.ACCESS_POINT, "vendor": "Cisco",
        "model": "Cisco 9800-L", "location": "Server Room A - Rack 4",
        "thresholds": {"temp_warn": 55, "temp_critical": 70,
                       "cpu_warn": 65, "cpu_critical": 85},
    },
]


def seed_devices():
    create_tables_sync()
    engine = create_engine(DATABASE_URL)

    with Session(engine) as session:
        existing = session.query(NetworkDevice).count()
        if existing > 0:
            logger.info(f"Devices already seeded ({existing} found) — skipping")
            return

        for d in DEMO_DEVICES:
            thresh_data = d.pop("thresholds", {})
            device = NetworkDevice(**d, status=DeviceStatus.ONLINE, is_monitored=True)
            session.add(device)
            session.flush()

            thresh = DeviceThreshold(device_id=device.id, **thresh_data)
            session.add(thresh)

        session.commit()
        logger.info(f"✅ Seeded {len(DEMO_DEVICES)} demo network devices")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    seed_devices()
