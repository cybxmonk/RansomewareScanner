#!/usr/bin/env python3
"""
Enhanced ransomware detector - With specific detection for bugsoft.exe sample
"""

import os
import sys
import math
import hashlib
import binascii
import logging
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Known ransomware signatures ( 