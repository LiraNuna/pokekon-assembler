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


def iw_op(name, mask):
    def encoder(arguments):
        waddress, byte = check_argument_count(name, arguments, 2)
        return bytearray([mask, parse_literal_byte(waddress), parse_literal_byte(byte)])

    return encoder


def ani(arguments):
    register, byte = check_argument_count('ani', arguments, 2)
    byte = parse_literal_byte(byte)

    if register == 'a':
        return bytearray([0x07, byte])

    extended_registers = {
        'v': 0x08,
        'a': 0x09,
        'b': 0x0A,
        'c': 0x0B,
        'd': 0x0C,
        'e': 0x0D,
        'h': 0x0E,
        'l': 0x0F,
        'pa': 0x88,
        'pb': 0x89,
        'pc': 0x8A,
        'mk': 0x8B,
    }
    if register not in extended_registers:
        raise ParseError(f'invalid register {register} for instruction')

    return bytearray([0x64, extended_registers[register]])


instruction_table = {
    'nop': no_arg('nop', 0x00),
    'hlt': no_arg('hlt', 0x01),
    'ret': no_arg('ret', 0x08),
    'sio': no_arg('sio', 0x09),

    'inx': high_4bit('inx', 0x02),
    'dcx': high_4bit('dcx', 0x03),
    'lxi': high_4bit('inx', 0x04),
    'ani': ani,

    'aniw': iw_op('aniw', 0x05),
    'oriw': iw_op('oriw', 0x15),
    'gtiw': iw_op('gtiw', 0x25),
    'ltiw': iw_op('ltiw', 0x35),
    'oniw': iw_op('oniw', 0x45),
    'offiw': iw_op('offiw', 0x55),
    'neiw': iw_op('neiw', 0x65),
    'eqiw': iw_op('eqiw', 0x75),
}

if __name__ == '__main__':
    with open('test.as', 'rt') as f:
        for line_number, line in enumerate(f):
            if not line.strip():
                continue

            line = line.strip()
            if line.startswith('#'):
                continue

            instruction, _, arguments = line.partition(' ')
            instruction = instruction.lower().strip()
            arguments = list(map(lambda arg: arg.strip(), filter(None, arguments.lower().split(','))))

            try:
                print(instruction_table[instruction](arguments))
            except ParseError as p:
                print(f"Parse error on line {line_number}: {p}")
