# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for the Switch integration configuration template."""

from pathlib import Path

import pytest
import yaml
from ansible.plugins.filter.core import to_nice_yaml
from jinja2 import Environment, FileSystemLoader


@pytest.mark.parametrize("software_image", [None, "", "nxos64-cs.10.6.4.M.bin"])
def test_poap_software_image_reaches_rendered_module_config(software_image):
    """Render optional POAP image selection into the module's configuration."""
    template_dir = Path(__file__).resolve().parents[2]
    template_dir /= "integration/targets/nd_manage_switches/templates"
    environment = Environment(loader=FileSystemLoader(template_dir))
    environment.filters["to_nice_yaml"] = to_nice_yaml
    poap = {"serial_number": "NEW123", "hostname": "leaf-1"}
    if software_image is not None:
        poap["software_image"] = software_image

    rendered = environment.get_template("nd_manage_switches_conf.j2").render(
        switch_conf=[{"seed_ip": "192.0.2.10", "role": "leaf", "poap": poap}],
        switch_username="admin",
        switch_password="password",
    )
    config = yaml.safe_load(rendered)

    assert config[0]["poap"]["serial_number"] == "NEW123"
    assert config[0]["poap"]["hostname"] == "leaf-1"
    if software_image:
        assert config[0]["poap"]["software_image"] == software_image
    else:
        assert "software_image" not in config[0]["poap"]
