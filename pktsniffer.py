
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="Packet Sniffer")

    parser.add_argument('-r', '--filename')
    parser.add_argument('-c', '--count')
    args = parser.parse_args()
    print(args.filename,args.count)


if __name__ == '__main__':
    main()