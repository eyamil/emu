class CPU {

    static register_map = new Map([["fp", 11], ["ip", 12], ["sp", 13], 
    ["lr", 14], ["pc", 15]]);

    constructor(memory = null) {
        this.memory = memory;
        this.registers = new Array(16);
        this.bit_flags = {
            N: false,
            Z: false,
            C: false,
            V: false,
            Q: false,
            J: false,
            GE: false,
            E: false,
            A: false,
            I: false,
            F: false,
            T: false,
            M: false
        }
        
    }

    
}