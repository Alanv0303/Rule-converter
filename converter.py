#!/usr/bin/env python3
"""
sigma_to_wazuh.py

Simple Sigma -> Wazuh rule converter.

Usage:
  python3 sigma_to_wazuh.py input_sigma.yml -o wazuh_rules.xml --start-id 100000 --group "sigma-conversion" --level 10

What it supports (reasonable defaults):
- Reads a Sigma rule YAML (or a file containing multiple YAML documents).
- Extracts top-level fields: title, id, description, level(if present) and detection-> selections and condition.
- For each Sigma rule it converts selection blocks into Wazuh <field name="...">value</field> entries when possible.
- If a value is a list, it creates a PCRE-style OR regex and emits a <regex> element.
- If the Sigma condition references multiple selections (e.g. "selection1 or selection2"), the converter will create a single Wazuh <rule> with multiple <field> / <regex> entries that must all match (simple approximation). Complex Sigma logic (NOT, nested parentheses, '1 of them') is approximated by combining patterns into a regex on the full log.

Notes & limitations:
- This is a pragmatic converter aimed at creating a good starting point for manual refinement. Sigma -> Wazuh is not a 1:1 mapping in general because Sigma is higher-level and expressive.
- You should review & test generated rules before deploying to production. Use ID range 100000-120000 for custom rules.

"""

import argparse
import sys
import yaml
import xml.etree.ElementTree as ET
from xml.dom import minidom
import re


def pretty_xml(elem: ET.Element) -> str:
    rough = ET.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough)
    return reparsed.toprettyxml(indent='  ')


def sigma_value_to_regex(value):
    """Turn a sigma value or list into a regex string safe for Wazuh PCRE2 use."""
    if isinstance(value, list):
        # Escape each item and join with |
        escaped = [re.escape(str(v)) for v in value]
        return r"(?:" + r"|".join(escaped) + r")"
    else:
        return re.escape(str(value))


def build_rule_xml(rule_obj, rule_id, group_name, default_level):
    # Create <group name="..."> wrapper
    rule_el = ET.Element('rule')
    rule_el.set('id', str(rule_id))

    # Level: use sigma level if exists else default
    level = rule_obj.get('level') or default_level
    rule_el.set('level', str(level))

    # Add description/title
    title = rule_obj.get('title') or rule_obj.get('id') or f"sigma_rule_{rule_id}"
    desc = ET.SubElement(rule_el, 'description')
    desc.text = title

    # Optional full description
    if rule_obj.get('description'):
        desc2 = ET.SubElement(rule_el, 'mitre_description')
        desc2.text = rule_obj.get('description')

    # decoded_as if logsource product is known
    logsource = rule_obj.get('logsource', {})
    product = None
    if isinstance(logsource, dict):
        product = logsource.get('product') or logsource.get('service') or logsource.get('category')
    if product:
        decoded = ET.SubElement(rule_el, 'decoded_as')
        decoded.text = str(product)

    # Detection -> selections
    detection = rule_obj.get('detection', {})
    # Flatten selections: selection blocks like 'selection', 'selection1', 'sel' etc.
    selections = {}
    for k, v in detection.items():
        if k == 'condition':
            continue
        # Treat non-condition keys as selection groups
        selections[k] = v

    condition = detection.get('condition')

    # If selections present, map them to <field> or <regex>
    if selections:
        # For each selection group, create submatchers
        # If condition references specific selections, we'll keep their names
        referenced = []
        if condition:
            # crude find of selection names in condition
            referenced = re.findall(r"\b([A-Za-z0-9_]+)\b", condition)
            # remove logical words
            referenced = [r for r in referenced if r.lower() not in ('and', 'or', 'not', 'of')]

        # If no explicit referenced selections, use all
        if not referenced:
            referenced = list(selections.keys())

        # For each referenced selection group, add its field entries
        for sel_name in referenced:
            sel = selections.get(sel_name)
            if not sel:
                continue
            # sel is typically a dict of field->value(s)
            if isinstance(sel, dict):
                for field_name, field_value in sel.items():
                    # If field_value is a dict it might contain operators - skip complex cases
                    if isinstance(field_value, dict):
                        # Fallback: create a regex from stringified dict
                        r = sigma_value_to_regex(field_value)
                        regex_el = ET.SubElement(rule_el, 'regex')
                        regex_el.text = r
                    else:
                        # If list -> regex
                        if isinstance(field_value, list):
                            regex_el = ET.SubElement(rule_el, 'regex')
                            regex_el.text = sigma_value_to_regex(field_value)
                        else:
                            field_el = ET.SubElement(rule_el, 'field')
                            field_el.set('name', str(field_name))
                            field_el.text = str(field_value)
            else:
                # The selection block is not a dict (e.g. a raw list) - make a regex
                regex_el = ET.SubElement(rule_el, 'regex')
                regex_el.text = sigma_value_to_regex(sel)

    else:
        # No selections: fallback create a regex from detection 'search'
        # If there's a simple search pattern, put it as regex
        for k in ('search',):
            if detection.get(k):
                r = sigma_value_to_regex(detection.get(k))
                regex_el = ET.SubElement(rule_el, 'regex')
                regex_el.text = r

    # Add metadata
    meta = rule_obj.get('tags') or rule_obj.get('references') or None
    if meta:
        # convert to a single string under 'group'
        groupmeta = ET.SubElement(rule_el, 'group')
        if isinstance(meta, list):
            groupmeta.text = ','.join(map(str, meta))
        else:
            groupmeta.text = str(meta)

    return rule_el


def convert_file(infile, outfile, start_id=100000, group_name='sigma-conversion', default_level=10):
    with open(infile, 'r') as f:
        docs = list(yaml.safe_load_all(f))

    root = ET.Element('group')
    root.set('name', group_name)

    current_id = start_id
    for doc in docs:
        if not doc:
            continue
        # Support both Sigma single-rule structure and some collections
        # If the file contains a top-level 'title' treat it as a single rule
        if isinstance(doc, dict) and ('title' in doc or 'detection' in doc):
            rule_xml = build_rule_xml(doc, current_id, group_name, default_level)
            root.append(rule_xml)
            current_id += 1
        else:
            # Possibly a dict of rules - attempt to find rules inside
            # For simplicity iterate keys that look like rules
            for maybe_rule in (v for v in (doc.values() if isinstance(doc, dict) else []) if isinstance(v, dict)):
                rule_xml = build_rule_xml(maybe_rule, current_id, group_name, default_level)
                root.append(rule_xml)
                current_id += 1

    # Write to outfile pretty
    pretty = pretty_xml(root)
    with open(outfile, 'w') as f:
        f.write(pretty)

    print(f"Converted {len(list(docs))} sigma documents -> {outfile} (IDs starting at {start_id})")


def main():
    parser = argparse.ArgumentParser(description='Convert Sigma rules (YAML) to a basic Wazuh rules XML file.')
    parser.add_argument('input', help='Input Sigma YAML file (can contain multiple --- documents)')
    parser.add_argument('-o', '--output', default='wazuh_rules.xml', help='Output XML filename')
    parser.add_argument('--start-id', type=int, default=100000, help='Starting rule id (default 100000)')
    parser.add_argument('--group', default='sigma-conversion', help='Wazuh rule group name')
    parser.add_argument('--level', type=int, default=10, help='Default alert level to assign')

    args = parser.parse_args()

    convert_file(args.input, args.output, start_id=args.start_id, group_name=args.group, default_level=args.level)


if __name__ == '__main__':
    main()