import sys
import os
import glob

"""
converts python unicorn bindings consts into nim consts source files
"""

def nimify(path):
    data = open(path, "r").readlines()
    lines = []
    lines.append("const\n")

    for line in data:
        lines.append("  {}".format(line.replace(" =", "* =")))

    return "".join(lines)

def process():
    exists = lambda d: os.path.isdir(d) and os.path.exists(d)

    if len(sys.argv) < 3:
        print("usage: {} <python const folder> <output folder>".format(sys.argv[0]))
        return
    
    input_folder = os.path.abspath(sys.argv[1])
    output_folder = os.path.abspath(sys.argv[2])

    if not exists(input_folder):
        print("Input path {} is wrong os does not exists".format(input_folder))
        return

    if not exists(output_folder):
        print("Output path {} is wrong os does not exists".format(output_folder))
        return
    
    inputs = glob.glob(input_folder+"/*_const.py")

    for file in inputs:
        basename = os.path.basename(file)

        if "unicorn" not in basename:
            result = nimify(file)
            filename = basename.replace(".py", ".nim")
            open("{}/{}".format(output_folder, filename), "w").write(result)


if __name__ == "__main__":
    process()
