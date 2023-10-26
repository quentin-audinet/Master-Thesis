TARGET	:= trace_program
TEST	:= test

CC		:= gcc
SOURCES	:= \
	trace_program.c

ECHO    := echo -e '\t'
RM		:= rm -f
CHOWN_ROOT	:= sudo chown root:root
CHMOD_ROOT	:= sudo chmod 4555


.PHONY:
all: $(TARGET) $(TEST)

$(TARGET): $(SOURCES)
	@$(ECHO) CC $(TARGET)
	@$(CC) -o $(TARGET) $(SOURCES)
	@$(ECHO) SETUID $(TARGET)
	@$(CHOWN_ROOT) $(TARGET)
	@$(CHMOD_ROOT) $(TARGET)

.PHONY:
clean:
	@$(ECHO) RM $(TARGET)
	@$(RM) $(TARGET)
	@$(ECHO) RM $(TEST)
	@$(RM) $(TEST)
	@$(ECHO) RM output
	@$(RM) output

$(TEST): $(TEST).c
	@$(ECHO) CC $(TEST)
	@$(CC) -o $(TEST) $(TEST).c

.PHONY:
run_test: $(TARGET) $(TEST)
	./$(TARGET) $(TEST)