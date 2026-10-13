// Trusted static exporter. This script never invokes target code or the decompiler.
// @category AutoReverse
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Register;
import com.google.gson.GsonBuilder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class ExportRawPcode extends HeadlessScript {
    private Map<String, Object> object(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < values.length; i += 2) {
            result.put((String) values[i], values[i + 1]);
        }
        return result;
    }

    private String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private Map<String, Object> address(Address value) {
        if (value == null) return null;
        return object("space", value.getAddressSpace().getName(), "offset", hex(value.getOffset()));
    }

    private List<Object> ranges(AddressSetView set) {
        List<Object> result = new ArrayList<>();
        AddressRangeIterator iterator = set.getAddressRanges();
        while (iterator.hasNext()) {
            AddressRange range = iterator.next();
            result.add(object("start", address(range.getMinAddress()),
                "end_inclusive", address(range.getMaxAddress()), "size_bytes", range.getLength()));
        }
        return result;
    }

    private Map<String, Object> varnode(Varnode value) {
        if (value == null) return null;
        AddressSpace space = value.getAddress().getAddressSpace();
        Register register = currentProgram.getRegister(value.getAddress(), value.getSize());
        return object("space", space.getName(), "space_id", space.getSpaceID(),
            "space_type", space.getType(), "space_bit_width", space.getSize(),
            "offset", hex(value.getOffset()), "size_bytes", value.getSize(),
            "bit_width", value.getSize() * 8, "is_constant", value.isConstant(),
            "is_register", value.isRegister(), "is_unique", value.isUnique(),
            "is_address", value.isAddress(), "register_name", register == null ? null : register.getName());
    }

    private Map<String, Object> operation(PcodeOp op, String source, int index) {
        List<Object> inputs = new ArrayList<>();
        for (Varnode value : op.getInputs()) inputs.add(varnode(value));
        Map<String, Object> callother = null;
        if (op.getOpcode() == PcodeOp.CALLOTHER) {
            long id = op.getInput(0).getOffset();
            callother = object("id", hex(id),
                "name", currentProgram.getLanguage().getUserDefinedOpName((int) id),
                "side_effects", "not_modeled");
        }
        Map<String, Object> memorySpace = null;
        if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
            int id = (int) op.getInput(0).getOffset();
            AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(id);
            memorySpace = object("space_id", id, "name", space == null ? null : space.getName());
        }
        return object("index", index, "opcode_id", op.getOpcode(), "opcode", op.getMnemonic(),
            "output", varnode(op.getOutput()), "inputs", inputs, "callother", callother,
            "memory_space", memorySpace, "instruction_source", source,
            "sequence", object("target", address(op.getSeqnum().getTarget()),
                "time", op.getSeqnum().getTime()));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || currentProgram == null) {
            throw new IllegalArgumentException("Exporter requires a program and one output JSON path");
        }
        Map<String, Object> root = object("schema_version", 1,
            "ir_kind", "ghidra_raw_pcode", "raw_pcode_method", "Instruction.getPcode()",
            "tool", object("name", "Ghidra", "version", Application.getApplicationVersion()),
            "java_runtime", object("version", System.getProperty("java.version"),
                "vendor", System.getProperty("java.vendor"), "user_home", System.getProperty("user.home")),
            "input", object("name", currentProgram.getName(),
                "sha256", currentProgram.getExecutableSHA256(), "format", currentProgram.getExecutableFormat()),
            "language", object("id", currentProgram.getLanguageID().toString(),
                "compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
                "address_bit_width", currentProgram.getDefaultPointerSize() * 8,
                "endianness", currentProgram.getLanguage().isBigEndian() ? "big" : "little"),
            "analysis_timed_out", analysisTimeoutOccurred(),
            "semantic_status", "not_verified", "target_executed", false);

        List<Object> memoryBlocks = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            memoryBlocks.add(object("name", block.getName(), "start", address(block.getStart()),
                "end_inclusive", address(block.getEnd()), "size_bytes", block.getSize(),
                "read", block.isRead(), "write", block.isWrite(), "execute", block.isExecute(),
                "initialized", block.isInitialized(), "overlay", block.isOverlay()));
        }
        root.put("memory_blocks", memoryBlocks);

        List<Object> functions = new ArrayList<>();
        FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
        while (functionIterator.hasNext()) {
            monitor.checkCancelled();
            Function function = functionIterator.next();
            functions.add(object("id", "function/" + function.getEntryPoint().toString(),
                "name", function.getName(), "entry", address(function.getEntryPoint()),
                "ranges", ranges(function.getBody()), "external", function.isExternal(),
                "thunk", function.isThunk(), "no_return", function.hasNoReturn(),
                "discovery_source", function.getSymbol().getSource().toString()));
        }
        root.put("functions", functions);

        List<Object> blocks = new ArrayList<>();
        SimpleBlockModel blockModel = new SimpleBlockModel(currentProgram);
        CodeBlockIterator blockIterator = blockModel.getCodeBlocks(monitor);
        while (blockIterator.hasNext()) {
            monitor.checkCancelled();
            CodeBlock block = blockIterator.next();
            List<Object> destinations = new ArrayList<>();
            CodeBlockReferenceIterator references = block.getDestinations(monitor);
            while (references.hasNext()) {
                CodeBlockReference reference = references.next();
                destinations.add(object("target", address(reference.getDestinationAddress()),
                    "referent", address(reference.getReferent()), "flow_type", reference.getFlowType().toString()));
            }
            blocks.add(object("id", "block/" + block.getFirstStartAddress().toString(),
                "entry", address(block.getFirstStartAddress()), "ranges", ranges(block),
                "destinations", destinations));
        }
        root.put("basic_blocks", blocks);

        List<Object> instructions = new ArrayList<>();
        InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
        long pcodeCount = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            String source = "instruction/" + instruction.getAddress().toString();
            byte[] bytes = instruction.getBytes();
            StringBuilder encoded = new StringBuilder();
            for (byte b : bytes) encoded.append(String.format("%02x", b & 0xff));
            List<Object> operands = new ArrayList<>();
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                operands.add(object("index", i, "type_flags", instruction.getOperandType(i),
                    "representation", instruction.getDefaultOperandRepresentation(i)));
            }
            List<Object> flows = new ArrayList<>();
            for (Address target : instruction.getFlows()) flows.add(address(target));
            Function function = currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
            CodeBlock block = blockModel.getFirstCodeBlockContaining(instruction.getAddress(), monitor);
            List<Object> operations = new ArrayList<>();
            PcodeOp[] pcode = instruction.getPcode();
            for (int i = 0; i < pcode.length; i++) operations.add(operation(pcode[i], source, i));
            pcodeCount += pcode.length;
            instructions.add(object("id", source, "address", address(instruction.getAddress()),
                "bytes", encoded.toString(), "size_bytes", bytes.length,
                "opcode", instruction.getMnemonicString(), "operands", operands,
                "instruction_source", source, "function_id", function == null ? null : "function/" + function.getEntryPoint().toString(),
                "basic_block_id", block == null ? null : "block/" + block.getFirstStartAddress().toString(),
                "flow", object("type", instruction.getFlowType().toString(),
                    "is_call", instruction.getFlowType().isCall(),
                    "is_jump", instruction.getFlowType().isJump(),
                    "is_terminal", instruction.getFlowType().isTerminal(),
                    "is_conditional", instruction.getFlowType().isConditional(),
                    "is_computed", instruction.getFlowType().isComputed(),
                    "fallthrough", address(instruction.getFallThrough()), "targets", flows),
                "pcode", operations, "lifted", true,
                "exception_semantics", "not_modeled"));
        }
        root.put("instructions", instructions);
        root.put("counts", object("functions", functions.size(), "basic_blocks", blocks.size(),
            "instructions", instructions.size(), "pcode_operations", pcodeCount));
        root.put("completeness", object("export_complete", true,
            "scope", "all_defined_instructions_functions_and_blocks_in_analyzed_program",
            "function_discovery_complete", false, "processor_semantics_complete", false));
        Path destination = Paths.get(args[0]).toAbsolutePath();
        Path temporary = destination.resolveSibling(destination.getFileName() + ".partial");
        Files.writeString(temporary, new GsonBuilder().serializeNulls().disableHtmlEscaping()
            .setPrettyPrinting().create().toJson(root), StandardCharsets.UTF_8);
        try {
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
        }
        println("AUTO_REVERSE_RAW_EXPORT_COMPLETE " + instructions.size());
    }
}
