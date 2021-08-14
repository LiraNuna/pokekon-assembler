class ParseError(IOError):
    pass


def no_arg(name, value):
    def encoder(arguments):
        if len(arguments) != 0:
            raise ParseError(f'instruction {name} takes no arguments')

        return value

    return encoder


def high_4bit(name, mask):
    register_map = {
        'sp': 0,
        'b': 1 << 4,
        'd': 2 << 4,
        'h': 3 << 4,
    }

    def encoder(arguments):
        if len(arguments) != 1:
            raise ParseError(f'instruction {name} takes one arguments')

        register, = arguments
        if register not in register_map:
            raise ParseError(f'unknown register {register} for {name}')

        return mask | register_map[register]

    return encoder


instruction_table = {
    'nop': no_arg('nop', 0x00),
    'hlt': no_arg('hlt', 0x01),
    'inx': high_4bit('inx', 0x02),
    'dcx': high_4bit('dcx', 0x03),
    'lxi': high_4bit('inx', 0x04),
}


if __name__ == '__main__':
    with open('test.as', 'rt') as f:
        for line_number, line in enumerate(f):
            if not line.strip():
                continue

            instruction, _, arguments = line.partition(' ')
            instruction = instruction.lower().strip()
            arguments = list(filter(None, arguments.lower().strip().split(' ')))

            try:
                print(hex(instruction_table[instruction](arguments)))
            except ParseError as p:
                print(f"Parse error on line {line_number}: {p}")
