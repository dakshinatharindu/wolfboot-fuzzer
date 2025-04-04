extern void          main(void);
typedef unsigned int uint32_t;

extern uint32_t  _start_vector;
extern uint32_t  _stored_data;
extern uint32_t  _start_data;
extern uint32_t  _end_data;
extern uint32_t  _start_bss;
extern uint32_t  _end_bss;
extern uint32_t  _end_stack;
extern uint32_t  _start_heap;
extern uint32_t  _global_pointer;

/* UART */
// #define UART0_BASE11              0x10013000UL
// #define UART_REG_TXDATA         (*(volatile uint32_t *)(UART0_BASE + 0x00))
// #define UART_REG_RXDATA         (*(volatile uint32_t *)(UART0_BASE + 0x04))
// #define UART_REG_TXCTRL         (*(volatile uint32_t *)(UART0_BASE + 0x08))
// #define UART_REG_RXCTRL         (*(volatile uint32_t *)(UART0_BASE + 0x0c))
// #define UART_REG_IE             (*(volatile uint32_t *)(UART0_BASE + 0x10))
// #define UART_REG_IP             (*(volatile uint32_t *)(UART0_BASE + 0x14))
// #define UART_REG_DIV            (*(volatile uint32_t *)(UART0_BASE + 0x18))

void __attribute__((naked,section(".init"))) _reset(void) {
  asm volatile("la gp, _global_pointer");
  asm volatile("la sp, _end_stack");

  /* Set up vectored interrupt, with IV starting at offset 0x100 */
  // asm volatile("csrw mtvec, %0":: "r"((uint8_t *)(&_start_vector) + 1));

  void _start(void);
  _start();
}


void _start(void) {
  main();
}
