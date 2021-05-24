#include <stdio.h>

#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)

#define ARM_MAX_BRP 16
#define ARM_MAX_WRP 16

/* Virtual debug register bases. */
#define AARCH64_DBG_REG_BVR 0
#define AARCH64_DBG_REG_BCR (AARCH64_DBG_REG_BVR + ARM_MAX_BRP)
#define AARCH64_DBG_REG_WVR (AARCH64_DBG_REG_BCR + ARM_MAX_BRP)
#define AARCH64_DBG_REG_WCR (AARCH64_DBG_REG_WVR + ARM_MAX_WRP)

/* Debug register names. */
#define AARCH64_DBG_REG_NAME_BVR bvr
#define AARCH64_DBG_REG_NAME_BCR bcr
#define AARCH64_DBG_REG_NAME_WVR wvr
#define AARCH64_DBG_REG_NAME_WCR wcr

#define isb() asm volatile("isb" : : : "memory")

#define read_sysreg(r)                                                         \
	({                                                                     \
		unsigned long long __val;                                      \
		asm volatile("mrs %0, " __stringify(r) : "=r"(__val));         \
		__val;                                                         \
	})
#define write_sysreg(v, r)                                                     \
	do {                                                                   \
		unsigned long long __val = (unsigned long long)(v);            \
		asm volatile("msr " __stringify(r) ", %x0" : : "rZ"(__val));   \
	} while (0)

#define AARCH64_DBG_READ(N, REG, VAL)                                          \
	do {                                                                   \
		VAL = read_sysreg(dbg##REG##N##_el0);                          \
	} while (0)

#define AARCH64_DBG_WRITE(N, REG, VAL)                                         \
	do {                                                                   \
		write_sysreg(VAL, dbg##REG##N##_el0);                          \
	} while (0)

#define READ_WB_REG_CASE(OFF, N, REG, VAL)                                     \
	case (OFF + N):                                                        \
		AARCH64_DBG_READ(N, REG, VAL);                                 \
		break

#define WRITE_WB_REG_CASE(OFF, N, REG, VAL)                                    \
	case (OFF + N):                                                        \
		AARCH64_DBG_WRITE(N, REG, VAL);                                \
		break

#define GEN_READ_WB_REG_CASES(OFF, REG, VAL)                                   \
	READ_WB_REG_CASE(OFF, 0, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 1, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 2, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 3, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 4, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 5, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 6, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 7, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 8, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 9, REG, VAL);                                    \
	READ_WB_REG_CASE(OFF, 10, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 11, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 12, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 13, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 14, REG, VAL);                                   \
	READ_WB_REG_CASE(OFF, 15, REG, VAL)

#define GEN_WRITE_WB_REG_CASES(OFF, REG, VAL)                                  \
	WRITE_WB_REG_CASE(OFF, 0, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 1, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 2, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 3, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 4, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 5, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 6, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 7, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 8, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 9, REG, VAL);                                   \
	WRITE_WB_REG_CASE(OFF, 10, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 11, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 12, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 13, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 14, REG, VAL);                                  \
	WRITE_WB_REG_CASE(OFF, 15, REG, VAL)

static unsigned long long read_wb_reg(int reg, int n)
{
	unsigned long long val = 0;

	switch (reg + n) {
		/* GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR, */
		/* 		      AARCH64_DBG_REG_NAME_BVR, val); */
		/* GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR, */
		/* 		      AARCH64_DBG_REG_NAME_BCR, val); */
		GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR,
				      AARCH64_DBG_REG_NAME_WVR, val);
		GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR,
				      AARCH64_DBG_REG_NAME_WCR, val);
	default:
		printf("attempt to read from unknown breakpoint register %d\n",
		       n);
	}

	return val;
}

static void write_wb_reg(int reg, int n, unsigned long long val)
{
	switch (reg + n) {
		/* GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BVR, */
		/* 		       AARCH64_DBG_REG_NAME_BVR, val); */
		/* GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BCR, */
		/* 		       AARCH64_DBG_REG_NAME_BCR, val); */
		GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WVR,
				       AARCH64_DBG_REG_NAME_WVR, val);
		GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WCR,
				       AARCH64_DBG_REG_NAME_WCR, val);
	default:
		printf("attempt to write to unknown breakpoint register %d\n",
		       n);
	}
	/* isb(); */
}

int main()
{
	unsigned int origin_value, control_value, check_value;
	int i = 0;
	origin_value = -1;
	control_value = 0x117;
	origin_value = read_wb_reg(AARCH64_DBG_REG_WCR, i);
	write_wb_reg(AARCH64_DBG_REG_WCR, i, control_value);
	check_value = read_wb_reg(AARCH64_DBG_REG_WCR, i);
	printf("origin: %x control: %x check: %x\n", origin_value,
	       control_value, check_value);
	return 0;
}
