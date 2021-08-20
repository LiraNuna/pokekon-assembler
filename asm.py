from typing import Callable
from typing import NamedTuple

COMMENT_PREFIXES = ('#', '//', ';')
RANGE_BYTE = range(0, 1 << 8)
WORD_RANGE = range(0, 1 << 16)


class Context:
    def __init__(self):
        self.line = ''
        self.line_number = 0
        self.offset = 0
        self.address = 0

        self.labels = {}
        self.patches = []

        self.result = bytearray()

    def emit(self, bytes):
        self.offset += len(bytes)
        self.address += len(bytes)
        self.result += bytes


class ParseError(IOError):
    pass


class Patch(NamedTuple):
    offset: int
    address: int
    encoder: Callable
    label: str
    line_number: int


def check_argument_count(name, arguments, size):
    if len(arguments) != size:
        raise ParseError(f'instruction {name} takes {size} arguments, {len(arguments)} given')

    return arguments


def parse_int(string, base, valid_range):
    try:
        value = int(string, base)
    except ValueError:
        raise ParseError(f'invalid literal with base {base}: {string}')

    if valid_range and value not in valid_range:
        raise ParseError(f'literal {string} ({value}) not in {valid_range}')

    return value


def parse_literal(argument, encoder, valid_range=None, placeholder=None):
    if argument.startswith(('0x', '-0x')):
        return encoder(parse_int(argument, 16, valid_range))
    if argument.startswith(('0', '-0')):
        return encoder(parse_int(argument, 7, valid_range))
    if argument.startswith(('-', '1', '2', '3', '4', '5', '6', '7', '8', '9')):
        return encoder(parse_int(argument, 10, valid_range))
    if argument in context.labels:
        if valid_range and context.labels[argument] not in valid_range:
            raise ParseError(f'label {argument} not in {valid_range}')

        return encoder(context.labels[argument])

    # Add the patch to the patch set
    context.patches.append(Patch(
        offset=context.offset,
        address=context.address,
        encoder=encoder,
        label=argument,
        line_number=context.line_number,
    ))

    # And return a placeholder
    if placeholder is not None:
        return placeholder
    if valid_range:
        return encoder(valid_range[0])

    raise ValueError("must have one of range or placeholder")


def parse_literal_byte(argument):
    return parse_literal(argument, lambda i: i.to_bytes(1, byteorder='little'), RANGE_BYTE)


def parse_literal_word(argument):
    return parse_literal(argument, lambda i: i.to_bytes(2, byteorder='little'), WORD_RANGE)


def prefix(value, op_encoder):
    def encoder(arguments):
        return bytearray([value]) + op_encoder(arguments)

    return encoder


def define_bytes(arguments):
    if not arguments:
        raise ParseError(f'cannot define empty bytes')

    for arg in arguments:
        context.emit(parse_literal_byte(arg))


def define_words(arguments):
    if not arguments:
        raise ParseError(f'cannot define empty words')

    for arg in arguments:
        context.emit(parse_literal_word(arg))


def no_arg(name, value):
    def encoder(arguments):
        check_argument_count(name, arguments, 0)
        context.emit(bytearray([value]))

    return encoder


def high_4bit(name, mask):
    register_map = {
        'sp': 0x00,
        'bc': 0x10,
        'de': 0x20,
        'hl': 0x30,
    }

    def encoder(arguments):
        register, = check_argument_count(name, arguments, 1)
        if register not in register_map:
            raise ParseError(f'unknown register {register} for {name}')

        context.emit(bytearray([mask | register_map[register]]))

    return encoder


def data_tfr_op(name, mask):
    def encoder(arguments):
        address, = check_argument_count(name, arguments, 1)

        context.emit(bytearray([0x70, mask]))
        context.emit(parse_literal_word(address))

    return encoder


def iw_op(name, mask):
    def encoder(arguments):
        waddress, byte = check_argument_count(name, arguments, 2)

        context.emit(bytearray([mask]))
        context.emit(parse_literal_byte(byte))

    return encoder


def wa_op(name, mask):
    def encoder(arguments):
        waddress, = check_argument_count(name, arguments, 1)

        context.emit(bytearray([mask]))
        context.emit(parse_literal_byte(waddress))

    return encoder


def abc_op(name, mask):
    registers = {
        'a': 0x01,
        'b': 0x02,
        'c': 0x03,
    }

    def encoder(arguments):
        register, = check_argument_count(name, arguments, 1)
        if register not in registers:
            raise ParseError(f'unknown register {register} for {name}')

        context.emit(bytearray([mask | registers[register]]))

    return encoder


def acc_op(name, mask):
    def encoder(arguments):
        register, = check_argument_count(name, arguments, 1)
        if register != 'a':
            raise ParseError(f'unknown register {register} for {name}')

        context.emit(bytearray([mask]))

    return encoder


def reg_acc_op(name, mask):
    registers = {
        ('v', 'a'): 0x00,
        ('a', 'a'): 0x01,
        ('b', 'a'): 0x02,
        ('c', 'a'): 0x03,
        ('d', 'a'): 0x04,
        ('e', 'a'): 0x05,
        ('h', 'a'): 0x06,
        ('l', 'a'): 0x07,

        ('a', 'v'): 0x80,
        ('a', 'b'): 0x82,
        ('a', 'c'): 0x83,
        ('a', 'd'): 0x84,
        ('a', 'e'): 0x85,
        ('a', 'h'): 0x86,
        ('a', 'l'): 0x87,
    }

    def encoder(arguments):
        regs = tuple(check_argument_count(name, arguments, 2))
        if regs not in registers:
            raise ParseError(f'invalid argument pair {regs} for {name}')

        context.emit(bytearray([0x60, mask | registers[regs]]))

    return encoder


def wr_word_op(name, mask):
    register_map = {
        'sp': 0x00,
        'bc': 0x10,
        'de': 0x20,
        'hl': 0x30,
    }

    def encoder(arguments):
        register, address = check_argument_count(name, arguments, 2)
        if register not in register_map:
            raise ParseError(f'unknown register {register} for {name}')

        context.emit(bytearray([mask | register_map[register]]))
        context.emit(parse_literal_word(address))

    return encoder


def stack_op(name, mask):
    register_map = {
        'v': 0x00,
        'bc': 0x10,
        'de': 0x20,
        'hl': 0x30,
    }

    def encoder(arguments):
        register, = check_argument_count(name, arguments, 1)
        if register not in register_map:
            raise ParseError(f'unknown register {register} for {name}')

        context.emit(bytearray([0x48, mask | register_map[register]]))

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
            context.emit(bytearray([0x06 | (opcode & 1) | ((opcode & 0x0E) << 3)]))
            context.emit(parse_literal_byte(byte))
        else:
            context.emit(bytearray([0x64, (opcode << 3) | registers[register]]))
            context.emit(parse_literal_byte(byte))

    return encoder


def word_acc_op(name, mask):
    registers = {
        'bc': 0x01,
        'de': 0x02,
        'hl': 0x03,
        'de+': 0x04,
        'hl+': 0x05,
        'de-': 0x06,
        'hl-': 0x07,
    }

    def encoder(arguments):
        register, = check_argument_count(name, arguments, 1)
        if register not in registers:
            raise ParseError(f'unknown register {register} for {name}')

        context.emit(bytearray([mask | registers[register]]))

    return encoder


def mov(name):
    registers = {
        'v': 0x68,
        'a': 0x69,
        'b': 0x6A,
        'c': 0x6B,
        'd': 0x6C,
        'e': 0x6D,
        'h': 0x6E,
        'l': 0x6F,
    }

    register_pairs = {
        ('a', 'b'): [0x0A],
        ('a', 'c'): [0x0B],
        ('a', 'd'): [0x0C],
        ('a', 'e'): [0x0D],
        ('a', 'h'): [0x0E],
        ('a', 'l'): [0x0F],

        ('b', 'a'): [0x1A],
        ('c', 'a'): [0x1B],
        ('d', 'a'): [0x1C],
        ('e', 'a'): [0x1D],
        ('h', 'a'): [0x1E],
        ('l', 'a'): [0x1F],

        ('a', 'pa'): [0x4C, 0xC0],
        ('a', 'pb'): [0x4C, 0xC1],
        ('a', 'pc'): [0x4C, 0xC2],
        ('a', 'mk'): [0x4C, 0xC3],
        ('a', 'mb'): [0x4C, 0xC4],
        ('a', 'mc'): [0x4C, 0xC5],
        ('a', 'tm0'): [0x4C, 0xC6],
        ('a', 'tm1'): [0x4C, 0xC7],
        ('a', 's'): [0x4C, 0xC8],
        ('a', 'tmm'): [0x4C, 0xC9],

        ('pa', 'a'): [0x4D, 0xC0],
        ('pb', 'a'): [0x4D, 0xC1],
        ('pc', 'a'): [0x4D, 0xC2],
        ('mk', 'a'): [0x4D, 0xC3],
        ('mb', 'a'): [0x4D, 0xC4],
        ('mc', 'a'): [0x4D, 0xC5],
        ('tm0', 'a'): [0x4D, 0xC6],
        ('tm1', 'a'): [0x4D, 0xC7],
        ('s', 'a'): [0x4D, 0xC8],
        ('tmm', 'a'): [0x4D, 0xC9],
    }

    def encoder(arguments):
        # First, assume reg, reg
        register_pair = tuple(check_argument_count(name, arguments, 2))
        if register_pair in register_pairs:
            return bytearray(register_pairs[register_pair])

        # Second, assume register, address
        register, address = register_pair
        if register in registers:
            context.emit(bytearray([0x70, 0x00 | registers[register]]))
            context.emit(parse_literal_word(address))
            return

        # Third, assume address, register
        address, register = register_pair
        if register in registers:
            context.emit(bytearray([0x70, 0x10 | registers[register]]))
            context.emit(parse_literal_word(address))
            return

        # Give up
        raise ParseError(f'unknown arguments {register_pair} for {name}')

    return encoder


def mvi(name):
    registers = {
        'a': 0x01,
        'b': 0x02,
        'c': 0x03,
        'd': 0x04,
        'e': 0x05,
        'h': 0x06,
        'l': 0x07,
    }

    def encoder(arguments):
        register, immediate = check_argument_count(name, arguments, 2)
        if register not in registers:
            raise ParseError(f'unknown register {register} for {name}')

        context.emit(bytearray([0x68 | registers[register]]))
        context.emit(parse_literal_byte(immediate))

    return encoder


def sknit(name):
    irqs = {
        'f0': 0x10,
        'ft': 0x11,
        'f1': 0x12,
        'f2': 0x13,
        'fs': 0x14,
    }

    def encoder(arguments):
        irq, = check_argument_count(name, arguments, 1)
        if irq not in irqs:
            raise ParseError(f'unknown irq {irq} for {name}')

        context.emit(bytearray([irqs[irq]]))

    return encoder


def skn(name):
    flags = {
        'cy': 0x1A,
        'z': 0x1C,
    }

    def encoder(arguments):
        flag, = check_argument_count(name, arguments, 1)
        if flag not in flags:
            raise ParseError(f'unknown irq {flag} for {name}')

        context.emit(bytearray([flags[flag]]))

    return encoder


def calt(name):
    def encoder(arguments):
        taddr, = check_argument_count(name, arguments, 1)

        context.emit(parse_literal(taddr, lambda i: i.to_bytes(1, byteorder='little'), range(0x80, 0xC0)))

    return encoder


def calf(name):
    def address_encoder(far_address):
        return bytearray([0x70 | (far_address >> 8), far_address & 0xFF])

    def encoder(arguments):
        faddr, = check_argument_count(name, arguments, 1)

        context.emit(parse_literal(faddr, address_encoder, range(0x800, 0x1000)))

    return encoder


def relative_byte(name):
    JUMP_RANGE = range(-0xFF, 0x100)

    def address_encoder(address):
        diff = address - context.address
        diff -= diff <= 0
        if diff not in JUMP_RANGE:
            raise ParseError(f'jump range ({diff}) not in {JUMP_RANGE}')

        if diff < 0:
            return bytearray([0x4F, diff + 0xFF])

        return bytearray([0x4E, diff - 2])

    def encoder(arguments):
        raddr, = check_argument_count(name, arguments, 1)

        context.emit(parse_literal(raddr, address_encoder, placeholder=bytearray([0x00, 0x00])))

    return encoder


def relative_word(name, opcode):
    def encoder(arguments):
        address, = check_argument_count(name, arguments, 1)

        context.emit(bytearray([opcode]))
        context.emit(parse_literal_word(address))

    return encoder


def relative_jump(name):
    JUMP_RANGE = range(-0x1F, 0x20)

    def address_encoder(address):
        diff = address - context.address
        diff -= diff <= 0
        if diff not in JUMP_RANGE:
            raise ParseError(f'jump range ({diff}) not in {JUMP_RANGE}')

        if diff < 0:
            return bytearray([0x100 + diff])

        return bytearray([0xBF + diff])

    def encoder(arguments):
        raddr, = check_argument_count(name, arguments, 1)

        context.emit(parse_literal(raddr, address_encoder, placeholder=bytearray([0])))

    return encoder


instruction_table = {
    'db': define_bytes,
    'dw': define_words,

    'nop': no_arg('nop', 0x00),
    'ret': no_arg('ret', 0x08),
    'rets': no_arg('ret', 0x18),
    'stm': no_arg('stm', 0x19),
    'sio': no_arg('sio', 0x09),
    'daa': no_arg('daa', 0x61),
    'reti': no_arg('reti', 0x62),
    'jb': no_arg('jb', 0x73),
    'ei': prefix(0x48, no_arg('ei', 0x20)),
    'di': prefix(0x48, no_arg('di', 0x24)),
    'clc': prefix(0x48, no_arg('clc', 0x2A)),
    'stc': prefix(0x48, no_arg('stc', 0x2B)),
    'pex': prefix(0x48, no_arg('pex', 0x2D)),
    'rld': prefix(0x48, no_arg('rld', 0x38)),
    'rrd': prefix(0x48, no_arg('rrd', 0x39)),
    'per': prefix(0x48, no_arg('per', 0x3C)),

    'rll': prefix(0x48, acc_op('rll', 0x30)),
    'rlr': prefix(0x48, acc_op('rlr', 0x31)),

    'skn': prefix(0x48, skn('skn')),
    'sknit': prefix(0x48, sknit('sknit')),

    'push': stack_op('push', 0x0E),
    'pop': stack_op('pop', 0x0F),

    'inx': high_4bit('inx', 0x02),
    'dcx': high_4bit('dcx', 0x03),
    'inr': abc_op('inr', 0x40),
    'dcr': abc_op('dcr', 0x50),

    'inrw': wa_op('inrw', 0x20),
    'ldaw': wa_op('ldaw', 0x28),
    'dcrw': wa_op('dcrw', 0x30),
    'staw': wa_op('staw', 0x38),

    'ldax': word_acc_op('ldax', 0x28),
    'stax': word_acc_op('stax', 0x38),
    'anax': prefix(0x70, word_acc_op('anax', 0x88)),
    'xrax': prefix(0x70, word_acc_op('xrax', 0x90)),
    'orax': prefix(0x70, word_acc_op('orax', 0x98)),
    'addncx': prefix(0x70, word_acc_op('addncx', 0xA0)),
    'gtax': prefix(0x70, word_acc_op('gtax', 0xA8)),
    'subnbx': prefix(0x70, word_acc_op('subnbx', 0xB0)),
    'ltax': prefix(0x70, word_acc_op('ltax', 0xB8)),
    'addx': prefix(0x70, word_acc_op('addx', 0xC0)),
    'onax': prefix(0x70, word_acc_op('addx', 0xC8)),
    'adcx': prefix(0x70, word_acc_op('adcx', 0xD0)),
    'offax': prefix(0x70, word_acc_op('offax', 0xD8)),
    'subx': prefix(0x70, word_acc_op('subx', 0xE0)),
    'neax': prefix(0x70, word_acc_op('neax', 0xE8)),
    'sbbx': prefix(0x70, word_acc_op('sbbx', 0xF0)),
    'eqax': prefix(0x70, word_acc_op('eqax', 0xF8)),

    'sspd': data_tfr_op('sspd', 0x0E),
    'lspd': data_tfr_op('lspd', 0x0F),
    'sbcd': data_tfr_op('sbcd', 0x1E),
    'lbcd': data_tfr_op('lbcd', 0x1F),
    'sded': data_tfr_op('sded', 0x2E),
    'lded': data_tfr_op('lded', 0x2F),
    'shld': data_tfr_op('shld', 0x3E),
    'lhld': data_tfr_op('lhld', 0x3F),
    'lxi': wr_word_op('lxi', 0x04),

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

    'ana': reg_acc_op('ana', 0x08),
    'xra': reg_acc_op('xra', 0x10),
    'ora': reg_acc_op('ora', 0x18),
    'addnc': reg_acc_op('addnc', 0x20),
    'gta': reg_acc_op('gta', 0x28),
    'subnb': reg_acc_op('subnb', 0x30),
    'lta': reg_acc_op('lta', 0x38),
    'add': reg_acc_op('add', 0x40),
    'adc': reg_acc_op('adc', 0x50),
    'sub': reg_acc_op('sub', 0x60),
    'nea': reg_acc_op('nea', 0x68),
    'sbb': reg_acc_op('sbb', 0x70),
    'eqa': reg_acc_op('eqa', 0x78),

    'aniw': iw_op('aniw', 0x05),
    'oriw': iw_op('oriw', 0x15),
    'gtiw': iw_op('gtiw', 0x25),
    'ltiw': iw_op('ltiw', 0x35),
    'oniw': iw_op('oniw', 0x45),
    'offiw': iw_op('offiw', 0x55),
    'neiw': iw_op('neiw', 0x65),
    'eqiw': iw_op('eqiw', 0x75),

    'mov': mov('mov'),
    'mvi': mvi('mvi'),
    'calt': calt('calt'),
    'calf': calf('calf'),

    'jr': relative_jump('jr'),
    'jre': relative_byte('jre'),
    'jmp': relative_word('jmp', 0x54),
    'call': relative_word('jmp', 0x44),
}

if __name__ == '__main__':
    BASE_ADDRESS = 0x4000

    context = Context()
    context.address = BASE_ADDRESS
    with open('jump_test.as', 'rt') as f, open('out.bin', 'wb') as out:
        for line_number, line in enumerate(f):
            line = line.strip()
            if not line or line.startswith(COMMENT_PREFIXES):
                continue
            for comment_prefix in COMMENT_PREFIXES:
                line, _, _ = line.partition(comment_prefix)

            instruction, _, arguments = line.partition(' ')
            instruction = instruction.lower().strip()
            arguments = list(map(lambda arg: arg.strip(), filter(None, arguments.lower().split(','))))

            context.line = line
            context.line_number = line_number

            try:
                if line.endswith(':'):
                    label = line.rstrip(':')
                    if label in context.labels:
                        raise ParseError(f"cannot redefine label '{label}'")

                    context.labels[label] = context.address
                    continue

                instruction, _, arguments = line.partition(' ')
                instruction = instruction.lower().strip()
                arguments = list(map(lambda arg: arg.strip(), filter(None, arguments.lower().split(','))))

                try:
                    instruction_table[instruction](arguments)
                except KeyError:
                    print(f"unknown instruction: {instruction}")
            except ParseError as p:
                print(f"Parse error on line {line_number + 1}: {p}")

        # 2nd pass: patch all forward-defined labels
        for patch in context.patches:
            try:
                context.offset = patch.offset
                context.address = patch.address
                context.line_number = patch.line_number

                to_patch = patch.encoder(context.labels[patch.label])
                context.result[patch.offset: patch.offset + len(to_patch)] = to_patch
            except KeyError:
                print(f"Parse error on line {patch.line_number + 1}: unknown label {patch.label}")
            except ParseError as p:
                print(f"Patch error on line {patch.line_number + 1}: {p}")

        out.write(context.result)
