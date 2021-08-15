RANGE_BYTE = range(0, 256)


class ParseError(IOError):
    pass


def check_argument_count(name, arguments, size):
    if len(arguments) != size:
        raise ParseError(f'instruction {name} takes {size} arguments, {len(arguments)} given')

    return arguments


def parse_int(string, base, valid_range):
    try:
        value = int(string, base)
    except ValueError as ve:
        raise ParseError(f'invalid literal with base {base}: {string}')

    if value not in valid_range:
        raise ParseError(f'literal {string} ({value}) not in {valid_range}')

    return value


def parse_literal_byte(argument):
    if (argument.startswith('0x')):
        return parse_int(argument, 16, RANGE_BYTE)
    if argument.startswith('0'):
        return parse_int(argument, 7, RANGE_BYTE)

    return parse_int(argument, 10, RANGE_BYTE)


def no_arg(name, value):
    def encoder(arguments):
        check_argument_count(name, arguments, 0)
        return bytearray([value])

    return encoder


def high_4bit(name, mask):
    register_map = {
        'sp': 0,
        'b': 1 << 4,
        'd': 2 << 4,
        'h': 3 << 4,
    }

    def encoder(arguments):
        register, = check_argument_count(name, arguments, 1)
        if register not in register_map:
            raise ParseError(f'unknown register {register} for {name}')

        return bytearray([mask | register_map[register]])

    return encoder


def aniw(arguments):
    waddress, byte = check_argument_count('aniw', arguments, 2)
    return bytearray([0x05, parse_literal_byte(waddress), parse_literal_byte(byte)])


instruction_table = {
    'nop': no_arg('nop', 0x00),
    'hlt': no_arg('hlt', 0x01),
    'inx': high_4bit('inx', 0x02),
    'dcx': high_4bit('dcx', 0x03),
    'lxi': high_4bit('inx', 0x04),
    'aniw': aniw,
}

if __name__ == '__main__':
    with open('test.as', 'rt') as f:
        for line_number, line in enumerate(f):
            if not line.strip():
                continue

            instruction, _, arguments = line.partition(' ')
            instruction = instruction.lower().strip()
            arguments = list(map(lambda arg: arg.strip(), filter(None, arguments.lower().strip().split(','))))

            try:
                print(instruction_table[instruction](arguments))
            except ParseError as p:
                print(f"Parse error on line {line_number}: {p}")
