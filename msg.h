#ifndef MSG_H
#define MSG_H

enum message_status {
    WORK,
    IDLE
};

enum message_type {
	ALLOCATE_BLOCK,
	FREE_BLOCK
};

struct message {
	uint64_t addr;
	uint32_t rkey;
	enum message_type type;
    volatile enum message_status status;
};

#endif /* MSG_H */
