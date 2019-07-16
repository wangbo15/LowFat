
typedef unsigned long bfd_vma;

struct line_head
{
  bfd_vma total_length;
  unsigned short version;
  unsigned char minimum_instruction_length;
  unsigned char maximum_ops_per_insn;
  unsigned char default_is_stmt;
  int line_base;
  unsigned char line_range;
  unsigned char opcode_base;
  unsigned char *standard_opcode_lengths;
};


void decode_line_info(unsigned char base, unsigned char range){
	struct line_head lh;
	
	lh.opcode_base = base;
	lh.line_range = range;
	
	unsigned char res = (255 - lh.opcode_base) / lh.line_range;
}

int main(){

	decode_line_info(1, 0);
	return 0;
}
