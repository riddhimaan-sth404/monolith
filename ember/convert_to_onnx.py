#!/usr/bin/env python3
"""Convert LightGBM models (text & pickle) to JSON for Go inference engine.

Usage:
    python convert_to_onnx.py <model_path> [output_path] [--name NAME]
"""

import json
import pickle
import sys
from pathlib import Path

try:
    import lightgbm as lgb
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'lightgbm'])
    import lightgbm as lgb


def convert_node(node):
    if node is None:
        return None
    if 'leaf_value' in node:
        return {'leaf_value': node['leaf_value']}

    result = {
        'split_feature': node['split_feature'],
        'default_left': node.get('default_left', True),
    }

    decision_type = node.get('decision_type', '<=')
    threshold = node['threshold']

    if isinstance(threshold, list):
        result['split_threshold'] = '||'.join(str(int(x)) for x in sorted(threshold))
    elif isinstance(threshold, str) and '||' in threshold:
        result['split_threshold'] = threshold
    elif isinstance(threshold, str):
        result['split_threshold'] = threshold
    else:
        result['split_threshold'] = float(threshold)

    result['left'] = convert_node(node.get('left_child'))
    result['right'] = convert_node(node.get('right_child'))
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Convert LightGBM model to JSON')
    parser.add_argument('model_path', help='Path to LightGBM .model file')
    parser.add_argument('output_path', nargs='?', help='Output JSON path')
    parser.add_argument('--name', help='Model name (default: derived from filename)')
    parser.add_argument('--num-features', type=int, help='Override feature count')

    args = parser.parse_args()

    model_path = Path(args.model_path)
    output_path = Path(args.output_path) if args.output_path else None
    model_name = args.name or model_path.stem

    print(f"Loading {model_path}...")

    data = model_path.read_bytes()
    is_pickle = data[0] == 0x80

    if is_pickle:
        print("Detected pickle format")
        objs = pickle.loads(data)
        if isinstance(objs, list):
            print(f"  List of {len(objs)} objects")
            all_trees = []
            max_feat = -1
            for bst in objs:
                if not hasattr(bst, 'dump_model'):
                    continue
                try:
                    dump = bst.dump_model()
                except Exception:
                    continue
                mf = dump.get('max_feature_idx', -1)
                if mf > max_feat:
                    max_feat = mf
                for ti in dump.get('tree_info', []):
                    ts = ti.get('tree_structure')
                    if ts is not None:
                        all_trees.append(ts)

            num_features = args.num_features or (max_feat + 1 if max_feat >= 0 else 2381)
            trees = [convert_node(ts) for ts in all_trees]
            model_json = {
                'name': model_name,
                'task': 'binary',
                'num_classes': 1,
                'num_features': num_features,
                'trees': trees,
            }
            print(f"  Collected {len(trees)} trees, {num_features} features")
        else:
            raise ValueError(f"Unexpected pickle type: {type(objs)}")
    else:
        print("Detected text format")
        bst = lgb.Booster(model_file=str(model_path))
        dump = bst.dump_model()
        tree_info = dump.get('tree_info', [])
        trees = [convert_node(ti['tree_structure']) for ti in tree_info if ti.get('tree_structure')]
        max_feat = dump.get('max_feature_idx', -1)
        num_features = args.num_features or (max_feat + 1 if max_feat >= 0 else 2381)
        model_json = {
            'name': model_name,
            'task': 'binary',
            'num_classes': 1,
            'num_features': num_features,
            'trees': trees,
        }
        print(f"  {len(trees)} trees, {num_features} features")

    if output_path is None:
        output_path = model_path.parent / f'{model_name}_converted.json'

    output_path.write_text(json.dumps(model_json, separators=(',', ':')), encoding='utf-8')
    print(f"Wrote {output_path} ({output_path.stat().st_size} bytes)")


if __name__ == '__main__':
    main()
