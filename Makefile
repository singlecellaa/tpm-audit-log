CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude
LDFLAGS ?= -ltss2-esys -ltss2-rc -ltss2-tctildr -ltss2-mu -lcrypto -lpthread

SRC := src/main.c src/log_listener.c src/hash_chain.c src/tpm_signer.c src/storage.c src/verification.c src/cli.c src/tpm_nv.c src/sig_verify.c
OBJDIR := build/obj
OBJ := $(addprefix $(OBJDIR)/,$(notdir $(SRC:.c=.o)))
BIN := build/auditlog

all: $(BIN)

$(BIN): $(OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: src/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)
	rmdir --ignore-fail-on-non-empty $(OBJDIR) 2>/dev/null || true

format:
	clang-format -i $(SRC) include/*.h

.PHONY: all clean format
