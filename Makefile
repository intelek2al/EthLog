NAME = ethlog

CMPL = gcc

OBJD = obj

SRCF = $(wildcard src/*.c)

INCF = $(wildcard inc/*.h)

INCD = inc

OBJO = $(SRCF:src%.c=obj%.o)

COMPILE = $(CMPL) $(OBJO) -o $(NAME) -lpcap -lpthread

all: install


$(OBJD):
	@mkdir -p $@

install: $(OBJD) $(OBJO)
	@$(COMPILE)

$(OBJD)/%.o: src/%.c $(INC)
	@$(CC) $(CFLGS) -c -o $@ $< -I$(INCD)

uninstall: clean
	@rm -rf $(NAME)

clean:
	@rm -rf obj

reinstall: uninstall all

