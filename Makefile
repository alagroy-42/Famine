# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: alagroy- <alagroy-@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/09 14:49:38 by alagroy-          #+#    #+#              #
#    Updated: 2022/02/09 15:28:42 by alagroy-         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = famine

SRCS = famine.s
OBJDIR = ./.objs/
SRCDIR = ./srcs/
OBJ_FILES = $(SRCS:.s=.o)
OBJS = $(addprefix $(OBJDIR), $(OBJ_FILES))
INCLUDES = ./srcs/defines.s

all : $(OBJDIR) $(NAME)

$(NAME): $(OBJS)
	ld -o $@ $<
	printf "\n\033[0;32m[$(NAME)] Linking [OK]\n\033[0;0m"

$(OBJDIR)%.o: $(SRCDIR)%.s $(INCLUDES) Makefile 
	nasm -i $(SRCDIR) -f elf64 -o $@ $<
	printf "\033[0;32m[$(NAME)] Compilation [$<]                 \r\033[0m"

$(OBJDIR):
	mkdir -p $@

clean:
	$(RM) -Rf $(OBJDIR)
	printf "\033[0;31m[$(NAME)] Clean [OK]\n"

fclean: clean
	$(RM) $(NAME)
	printf "\033[0;31m[$(NAME)] Fclean [OK]\n"

re: fclean all

.PHONY: clean re fclean all
.SILENT: