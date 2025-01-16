#include <unistd.h>
#include <pthread.h>
#include <string.h>
/* For Debug */
#include <stdio.h>

/*
stack (high to low) Contains automatic variables, function aruguments, copy of base pointer etc.
heap (brk: points to the end of the heap): Contains the dynamically allocated data.
bss (Block Started by Symbol) Contains zero-initialized static data. Static data uninitialized in program is initialized 0 and goes here
data (initialized variables)
test (low to high)

function: sbrk():
sbrk(0): gives the current address of program break.
sbrk(x): Calling sbrk(x) with a positive value increments brk by x bytes, as a result allocating memory.
sbrk(-x): negative value decrements brk by x bytes, as result releasing memory
failure, sbrk() return (void*) -1

some new alternatives:
1. mmap()

sbrk() is nor really thread safe
it can only grow or shrink in LIFO order.
man 2 sbrk

sbrk() for  allocating memoy that's not too big in size.

freeing this memory
free(ptr)

free memory & release memory
free(ptr): free the memory block pointed to by ptr, which must have been returned by a previouds call to malloc(), calloc(), realloc()

freeing a block doses not necessarily mean we release back to OS
free only marked block as free

head is contiguous

To store for every block of allocated memory
1. size
2. Whether a block is free or not-free?
3. struct header_t *next; (a bit of like link list)
4. 
*/

typedef char ALIGN[16];

union header { // Union can allow all member use same block memory (Describe Multi-variable Situation)
    struct {
        size_t size;
        unsigned is_free;
        union header *next;
    } s;
    ALIGN stub;
};

typedef union header header_t;

// head and tail pointer to keep track of the list
header_t *head = NULL, *tail = NULL;

// To prevent two or more threads from concurrently accessing memory
// put a basic locking mechanism in place
// Before every action on memory you have to acquire the lock, and once you are done you have to release the lock

// Global lock
pthread_mutex_t global_malloc_lock;


// It traverses the linked list and see if there already exist block of memory
// that marked as free and can accomodate the given size.
// Here, we take a first-fit approach in searching the linekd list

header_t *get_free_block(size_t size)
{
    header_t *curr = head;
    // traverse the linked list (memory block) to found free memory block
    while (curr) {
        // when block is free && size is not bigger
        if (curr->s.is_free && curr->s.size >= size) {
            return curr;
        }
        curr = curr->s.next;
    }
    return NULL;
}

// 
void *malloc(size_t size) 
{
    size_t total_size; // get size
    void *block; // pointer to block
    header_t *header; // block head

    if (!size) { // Check  allocate size
        return NULL;
    }

    pthread_mutex_lock(&global_malloc_lock); // get_free_block() acquire the lock
    header = get_free_block(size); // first-fit

    // If sufficiently block is found
    if (header) {
        // set is not-free
        header->s.is_free = 0;
        // release the global lock
        pthread_mutex_unlock(&global_malloc_lock);
        // it ponits to the byte right after the end of the header (first byte of the actual memory block)
        return (void*) (header + 1);
    }

    // extend the heap by calling sbrk
    // if we have not found a sufficiently large free block
    // requested size the OS to increment the program break
    total_size = sizeof(header_t) + size;
    // request operating system
    block = sbrk(total_size);

    // failed alloc sbrk return (void*) - 1
    if (block == (void*) - 1) {
        pthread_mutex_unlock(&global_malloc_lock);
        return NULL;
    }

    // Block
    header = block;
    header->s.size = size;
    header->s.is_free = 0;
    header->s.next = NULL;

    // if head is null
    if (!head) {
        head = header;
    }

    // if tail is not null
    // add new block after tail 
    if (tail) {
        tail->s.next = header;
    }

    // update tail
    tail = header;
    pthread_mutex_unlock(&global_malloc_lock);

    return (void*) (header + 1);
}

// free memory block
// block-to-freed is at he end of the heap
void free(void *block)
{
	header_t *header, *tmp;// header, tmp
	void *programbreak;

    // if block not exist
	if (!block)
		return;

	pthread_mutex_lock(&global_malloc_lock);

    // free head pointer to before
	header = (header_t* ) block - 1;

    // To check if the block to be freed is at the end of the heap
    // We first find the end of the current block
    // (char*)block + header->size (To check current block to be freed is at the end of the heap)
	programbreak = sbrk(0); // Get current program break

    // if it is at the end, we could shrink the size of the heap and release memory
	if ((char* )block + header->s.size == programbreak) {
        // if only one block
		if (head == tail) {
			head = tail = NULL;
		} else {
			tmp = head;
			while (tmp) {
                // find block before tail
				if(tmp->s.next == tail) {
					tmp->s.next = NULL;
					tail = tmp;
				}
				tmp = tmp->s.next;
			}
		}
        // Shrink heap space (negative num)
		sbrk(0 - sizeof(header_t) - header->s.size);
		pthread_mutex_unlock(&global_malloc_lock);
		return;
	}
	header->s.is_free = 1;
	pthread_mutex_unlock(&global_malloc_lock);
}

void *calloc(size_t num, size_t nsize)
{
	size_t size;
	void *block;
	if (!num || !nsize)
		return NULL;
	size = num * nsize;
	/* check mul overflow */
	if (nsize != size / num)
		return NULL;
	block = malloc(size);
	if (!block)
		return NULL;
	memset(block, 0, size);
	return block;
}

// realloc() changes the size of the given memory block to the size given
void *realloc(void *block, size_t size)
{
	header_t *header;
	void *ret;

    // Block not exist & size error
	if (!block || !size)
		return malloc(size);
 
	header = (header_t*)block - 1;

	if (header->s.size >= size)
		return block;

    // malloc bigger size
	ret = malloc(size);

	if (ret) {
        // copy data
		memcpy(ret, block, header->s.size);
		free(block);
	}

	return ret;
}

void print_mem_list()
{
	header_t *curr = head;
	printf("head = %p, tail = %p \n", (void*)head, (void*)tail);
	while(curr) {
		printf("addr = %p, size = %zu, is_free=%u, next=%p\n",
			(void*)curr, curr->s.size, curr->s.is_free, (void*)curr->s.next);
		curr = curr->s.next;
	}
}

int main() {
    int* a = malloc(sizeof(int));
    print_mem_list();
    return 0;
}