import sys

def arff2csv(arff_path, csv_path = None, _encoding = 'utf8'):
    with open(arff_path, 'r', encoding = _encoding) as fr:
        attributes = []
        if csv_path is None:
            csv_path = arff_path[:-4] + 'csv'  # *.arff -> *.csv
        write_sw = False
        with open(csv_path, 'w', encoding = _encoding) as fw:
            for line in fr.readlines():
                if write_sw:
                    fw.write(line)
                elif '@data' in line:
                    fw.write(','.join(attributes) + '\n')
                    write_sw = True
                # elif '@attribute' in line:
                    # attributes.append(line.split()[1])  # @attribute attribute_tag numeric
    print("Convert %s to %s" % (arff_path, csv_path))

def main():
    input_file = None
    output_file = None

    argc = len(sys.argv)
    if (argc < 2) or (argc > 3):
        print("Usage: %s input_file.arff [output_file.csv])" % sys.argv[0])
        sys.exit()
    elif argc == 3:
        # input_file = sys.argv[1]
        output_file = sys.argv[2]
    # else:
    input_file = sys.argv[1]

    arff2csv(input_file, output_file)

if __name__ == '__main__':
    main()
