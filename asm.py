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


def imm_data_transfer(name, opcode):
    registers = {
        'v': 0x00,
        'a': 0x01,
        'b': 0x02,
        'c': 0x03,
        'd': 0x04,
        'e': 0x05,
        'h': 0x06,
        'l': 0x07,
        # special registers
        'pa': 0x80,
        'pb': 0x81,
        'pc': 0x82,
        'mk': 0x83,
    }

    def encoder(arguments):
        register, byte = check_argument_count(name, arguments, 2)
        if register not in registers:
            raise ParseError(f'unknown register {register} for {name}')

        if register == 'a':
            return bytearray([0x06 | (opcode & 1) | ((opcode & 0x0E) << 3), parse_literal_byte(byte)])

        return bytearray([0x64, (opcode << 3) | registers[register], parse_literal_byte(byte)])

    return encoder


instruction_table = {
    'nop': no_arg('nop', 0x00),
    'ret': no_arg('ret', 0x08),
    'sio': no_arg('sio', 0x09),

    'inx': high_4bit('inx', 0x02),
    'dcx': high_4bit('dcx', 0x03),
    'lxi': high_4bit('inx', 0x04),

    'ani': imm_data_transfer('ani', 0x01),
    'xri': imm_data_transfer('xri', 0x02),
    'ori': imm_data_transfer('ori', 0x03),
    'adinc': imm_data_transfer('adinc', 0x04),
    'gti': imm_data_transfer('gti', 0x05),
    'suinb': imm_data_transfer('suinb', 0x06),
    'lti': imm_data_transfer('lti', 0x07),
    'adi': imm_data_transfer('adi', 0x08),
    'oni': imm_data_transfer('oni', 0x09),
    'aci': imm_data_transfer('aci', 0x0A),
    'offi': imm_data_transfer('offi', 0x0B),
    'sui': imm_data_transfer('sui', 0x0C),
    'nei': imm_data_transfer('nei', 0x0D),
    'sbi': imm_data_transfer('sbi', 0x0E),
    'eqi': imm_data_transfer('eqi', 0x0F),

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
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            if line.startswith('//'):
                continue

            instruction, _, arguments = line.partition(' ')
            instruction = instruction.lower().strip()
            arguments = list(map(lambda arg: arg.strip(), filter(None, arguments.lower().split(','))))

            try:
                result = instruction_table[instruction](arguments)
                for byte in result:
                    print(('0' + hex(byte).replace('0x', ''))[-2:], end=' ')
                print()
            except KeyError:
                print(f"unknown instruction: {instruction}")
            except ParseError as p:
                print(f"Parse error on line {line_number}: {p}")
