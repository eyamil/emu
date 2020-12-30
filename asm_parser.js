/*
let instr_set = ["add", "adc", "qadd", "sub", "sbc",
    "rsb", "qsub", "mul", "mla", "mls", "umull", "umlal", "smull", "umlal",
    "smull", "smlal", "udiv", "sdiv", "and", "bic", "orr", "orn", "eor",
    "cmp", "cmn", "tst", "teq", "mov", "lsr", "asr", "lsl", "ror", "rrx",
    "ldr", "str", "stmia", "ldm", "stm", "b", "bl", "bx",
    "blx", "cbz", "cbnz", "tbb", "tbh", "ldrex", "strex"];

let condition_codes = ["", "eq", "ne", "cs", "hs", "cc", "lo", "mi",
    "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"];

let register_map = new Map([["fp", 11], ["ip", 12], ["sp", 13],
["lr", 14], ["pc", 15]]);


let register_regex_str = (function () {
    let named_registers = ["fp", "ip", "sp", "lr", "pc"];
    let indexed_exp = "(?:r\\d{1,2})";
    let named_exp = "(?:" + named_registers.join("|") + ")";

    return (indexed_exp + "|" + named_exp);
})();

let literal_regex_str = (function () {
    let dec_lit = "(?:\\d+)";
    let bin_lit = "(?:0b[01]+)";
    let hex_lit = "(?:0x[0-9a-f]+)";

    return ("(?:#" + [dec_lit, bin_lit, hex_lit].join("|") + ")");
})();

let value_regex_str = register_regex_str + "|" + literal_regex_str;

let offset_regex_str = (function () {
    "\]" + value_regex_str + "(?:,\\s" + value_regex_str + ")?";
})();*/

let Instruction_Set = (function() {

    let unclamped_arith = ["add", "adc", "sub", "sbc", "rsb"];
    let clamped_arith = ["qadd", "qsub"];
    let basic_mul = ["mul"];
    let extra_mul_div = ["mla", "mls", "umull", "umlal", "smull", "smlal",
    "udiv", "sdiv"];
    let logic = ["and", "bic", "orr", "orn", "eor"];
    let tests = ["cmp", "cmn", "tst", "teq"];
    let move = ["mov"];
    let rot_shift = ["lsr", "lsl", "asr", "ror", "rrx"];
    let memory = ["ldr", "str"];
    let stack_specific = ["push", "pop"];
    let branch_label = ["b", "bl"];
    let branch_reg = ["bx", "blx"];
    
    class Instruction_Set {

        /* I'm pretty sure I won't need the following sets:
        static basic_arith = new Set(unclamped_arith.concat(clamped_arith));
        static mul_div = new Set(basic_mul.concat(extra_mul_div));
        static logic = new Set(logic);
        static tests = new Set(tests);
        static move = new Set(move);
        static rot_shift = new Set(rot_shift);
        static memory = new Set(memory.concat(stack_specific));
        static branch = new Set(branch_label.concat(branch_reg));
        */

        static flaggable = new Set(unclamped_arith.concat(logic, move, rot_shift));
        static omittable_dest_reg = new Set(unclamped_arith.concat(basic_mul, logic));
        static support_curly = new Set(stack_specific);
        static support_memloc = new Set(memory);
    
    }

    return(Instruction_Set);

})()

class Parser {

    static named_registers = new Set(["fp", "ip", "sp", "lr", "pc"]);

    static op_set = ["add", "adc", "qadd", "sub", "sbc",
    "rsb", "qsub", "mul", "mla", "mls", "umull", "umlal", "smull", "umlal",
    "smull", "smlal", "udiv", "sdiv", "and", "bic", "orr", "orn", "eor",
    "cmp", "cmn", "tst", "teq", "mov", "lsr", "asr", "lsl", "ror", "rrx",
    "ldr", "str", "stmia", "ldm", "stm", "b", "bl", "bx",
    "blx", "cbz", "cbnz", "tbb", "tbh", "ldrex", "strex"];

    static cd_set = ["eq", "ne", "cs", "hs", "cc", "lo", "mi",
    "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"];

    static tokenize(line) {
        // Match a .data segment, label, memory location, instr/lit/reg, {reg}:
        let seg = "(\\.\\w+)";
        let lab = "(^\\w+\\:)";
        let loc = "(\\[\\w+[\\s?,[\\w#]+]*\\])";
        let set = "(\\{\\w+[\\s?,[\\w#]+]*\\})";
        let wrd = "([\\w#]+)";
        let instr_fmt = wrd + "(?:" + wrd + "?" + wrd + "?" + wrd + "?)|(?:" +
        loc + ")|(?:" + set + ")";
        let line_fmt = seg + "|(?:" + lab + '?' + instr_fmt + "?)";

        let prep_rexp = [seg, lab, loc, instr_lit_reg, set].join('|');

        return(line.matchAll(prep_rexp, "g"));
    }

    static parse_register(reg_str) {
        // Check if it's a named register
        if (Parser.named_registers.has(reg_str)) {
            return({'type': 'register', 'id': reg_str});
        }
        // If not, pull out the register number
        let indices = reg_str.match(/^R(\d+)$/i);
        if (indices != null) {
            return({'type': 'register', 'id': indices[1]});
        }
        // If both failed:
        throw(new SyntaxError("Couldn't parse register '" + reg_str + "'"));
    }

    static parse_literal(int_lit) {
        // Check if it's in hex (leading #0x):
        let digits = int_lit.match(/^#0x([0-9a-f]+)$/i);
        if (digits != null) {
            return({'type': 'literal', 'value': parseInt(digits[1], 16)});
        }
        // Try binary (leading #0b):
        digits = int_lit.match(/^#0b([01]+)$/);
        if (digits != null) {
            return({'type': 'literal', 'value': parseInt(digits[1], 2)});
        }
        // Try decimal (leading #):
        digits = int_lit.match(/^#(\d+)$/);
        if (digits != null) {
            return({'type': 'literal', 'value': parseInt(digits[1], 10)});
        }
        // If all of those failed:
        throw(new SyntaxError("Couldn't parse int literal '" + int_lit + "'"));
    }

    static parse_val(val_str) {
        switch(true) {
            // Check for leading '#'         --> literal
            case val_str.match(/^#/) != null:
                return(Parser.parse_literal(val_str));
            // Check for leading r,f,s,i,l,p --> register
            case val_str.match(/^[rfsilp]/i) != null:
                return(Parser.parse_register(val_str));
            // Check for leading digit       --> helpful error
            case val_str.match(/^[0-9]/i) != null:
                throw(new SyntaxError("Literals must begin with '#'"));
            // Now we don't know wtf's going on:
            default:
                throw(new SyntaxError("Couldn't parse value '" + val_str + "'"));
        }
    }
    
    static parse_operands(op_str) {
        // Match "rm, ?(rn, shift)":
        let rm_pat = "^(#?[\\w]+)";
        let rn_shift_pat = "(?:,\\s?([\\w\\s,#]+))?$";
        let ops = op_str.match(rm_pat + rn_shift_pat);
        if (ops != null) {
            let [_, rm, rn_str] = ops;
            let op1 = Parser.parse_val(rm);
            if (rn_str != undefined) {
                let op2 = Parser.parse_opr2(rn_str);
                return([op1, op2]);
            }
            else {
                return([op1]);
            }
        }
        throw(new SyntaxError("Couldn't parse operand string '" + op_str + "'"));
    }

    static parse_opr2(op2_str) {
        // Match "rn, ?shift":
        let rn_pat = "^([\\w#]+)";
        let shift_pat =  "(?:,\\s?([#\\w\\s]+))?$";
        let ops = op2_str.match(rn_pat + shift_pat);
        if (ops != null) {
            if (ops[2] == undefined) {
                return(Parser.parse_val(ops[1]));
            }
            else {
                let val = Parser.parse_val(ops[1]);
                return(Parser.parse_shifter(ops[2], val));
            }
        }
        throw(new SyntaxError("Couldn't parse 2nd operand/shift '" + op2_str + "'"));
    }

    static parse_shifter(shift_str, val_to_shift) {
        // Match "asr/lsr/asl/lsl/ror value":
        let shift_instr_pat = "^((?:[al]sr)|(?:ror)|(?:lsl)|(?:rrx))";
        let val_pat = "(?:(?:\\s+)?([\\w#]+))$";
        let ops = shift_str.match(shift_instr_pat + val_pat, "i");
        if (ops != null) {
            let [_, instr, shift_by] = ops;
            if (instr == undefined) {
                throw(new SyntaxError("Couldn't parse shift type '" + shift_str + "'"));
            }
            else if (shift_by == undefined) {
                throw(new SyntaxError("Couldn't parse shift amount '" + shift_str + "'"));
            }
            let by = Parser.parse_val(shift_by);
            return({'type': instr, 'shift_by': by, 'val': val_to_shift});
        }
        throw(new SyntaxError("Couldn't parse shifter '" + shift_str + "'"));
    }

    static parse_memloc(loc_str) {
        // Just reuse operand parsing code for this:
        let contents = loc_str.match(/^\[(.*)\]$/);
        if (contents != null) {
            let [base, offset] = Parser.parse_operands(contents[1]);
            return({'type': 'memloc', 'base': base, 'offset': offset});
        }
        // Malformed offset because not even the first thing exists:
        throw(new SyntaxError("Couldn't parse memory location '" + loc_str + "'"));
    }

    static parse_set(set_str) {
        let elements = set_str.matchAll(/[\w-]+/g);
        let expanded_reg = [];
        for (let el of elements) {
            let reg_ind = el[0].match(/^r(\d+)-(\d+)$/i);
            if (reg_ind != null) {
                let start = parseInt(reg_ind[1]);
                let end = parseInt(reg_ind[2]);
                if (start < end) {
                    for (let i = start; i <= end; i++) {
                        expanded_reg.push("r" + i.toString());
                    }
                }
                else {
                    throw(new SyntaxError("Couldn't read register range '" 
                    + reg_ind[0] + "'"));
                }
            }
            else {
                let reg_named = el[0].match(/^(\w+)$/i);
                if (reg_named != null) {
                    expanded_reg.push(reg_named[0])
                }
                else {
                    throw(new SyntaxError("Couldn't read register '" + el[0] + "'"));
                }
            }
        }
        return(expanded_reg.map((x) => Parser.parse_register(x)));
    }

    static parse_op(instr) {
        // operation<extra><condition><set_flag>
        let op_regex = Parser.op_set.map((x) => ('(?:' + x + ')')).join('|');
        let cd_regex = Parser.cd_set.map((x) => ('(?:' + x + ')')).join('|');
        let flag_regex = "(s)?";
        let full_regex = '^(' + op_regex + ')(' + cd_regex + ')?' + flag_regex
        + '$';
        let parsed = instr.match(new RegExp(full_regex, "i"));
        if (parsed != null) {
            let [_, op, cd, s] = parsed;
            return({'type': 'instr', 'op': op, 'cd': cd, 's': (s != undefined)})
        }
        throw(new SyntaxError("Couldn't read instruction '" + instr + "'"));
    }

    static parse_instr(line) {
        let tokens = [... Parser.tokenize(line)];
        let instr = Parser.parse_instr(tokens[0]);
        if (instr.s && !Instruction_Set.flaggable.has(instr.op.toLowerCase())) {
            throw(new SyntaxError("Instruction '" + instr.op + "' does not " + 
            "support setting flags"));
        }
        
    }

    static parse_label() {}
}