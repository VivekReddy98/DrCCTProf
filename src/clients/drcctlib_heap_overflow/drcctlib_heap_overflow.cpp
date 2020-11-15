/*
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstddef>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"
#include "drwrap.h"
#include <unordered_map>
#include <iostream>
#include <unordered_set>
#include <list>

using namespace std;

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_with_addr_and_refsize_clean_call", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_with_addr_and_refsize_clean_call", format, \
                                          ##args)

static int tls_idx;

static file_t gTraceFile;

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, type, offs) *(type **)TLS_SLOT(tls_base, offs)
#define MINSERT instrlist_meta_preinsert
#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#endif

typedef struct _mem_ref_t {
    app_pc addr;
    size_t size;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
} per_thread_t;

#define RED_ZONE_WIDTH 20
#define TLS_MEM_REF_BUFF_SIZE 100
#define MAX_DEPTH_TO_BOTHER 6

unordered_set<uint64_t> ctxtMap;

/* Since Heap Memory is Thread agnostic, declaring them global wouldn't be a problem */
unordered_map<app_pc, context_handle_t> redMap;
unordered_map<app_pc, list<app_pc>> freeMap;

/* ------------------------------ Helper Wrapper Methods / Objects -------------------------- */
/* Malloc Functions */
static void
pre_malloc(void *wrapcxt, OUT void **user_data)
{
    /* malloc(size) */
    size_t sz = (size_t)drwrap_get_arg(wrapcxt, 0);
    *user_data = (void *)sz;
    sz++;
    drwrap_set_arg(wrapcxt, 0, (void*)sz);
}

static void
post_malloc(void *wrapcxt, void *user_data)
{
    context_handle_t malloc_ctxt = drcctlib_get_context_handle(drwrap_get_drcontext(wrapcxt), 0);
    app_pc start = (app_pc)drwrap_get_retval(wrapcxt);
    app_pc redZone = start + (size_t)user_data;

    printf("\nMalloc Context: %d, malloc start address: %p, nsize: %lu, RedZones: ", malloc_ctxt, start, (size_t)user_data);

    freeMap[start] = list<app_pc> {};
    for (app_pc i = redZone; i < redZone + RED_ZONE_WIDTH; i++){
        redMap[i] = malloc_ctxt;
        printf(" %p,", i);
        freeMap[start].push_back(i);
    }
}

// /* Calloc Functions */
// static void
// pre_calloc(void *wrapcxt, OUT void **user_data)
// {
//     /* calloc(numitems, size) */
//     size_t nitems = (size_t)drwrap_get_arg(wrapcxt, 0);
//     *user_data = (void *)nitems;
//     nitems++;
//     drwrap_set_arg(wrapcxt, 0, (void *)nitems);
// }
//
// TODO: nsize might not work in post_calloc
// static void
// post_calloc(void *wrapcxt, void *user_data)
// {
//     context_handle_t calloc_ctxt = drcctlib_get_context_handle(drwrap_get_drcontext(wrapcxt), 0);
//     app_pc start = (app_pc)drwrap_get_retval(wrapcxt);
//     app_pc redZone = start + (size_t)user_data;
//     size_t nsize = (size_t)drwrap_get_arg(wrapcxt, 1);
//
//     printf("\nCalloc Context: %d, calloc start address: %p, nsize: %lu, RedZone: ", calloc_ctxt, start, nsize);
//     freeMap[start] = list<app_pc> {};
//     for (app_pc i = redZone; i < redZone + nsize; i++){
//         redMap[i] = calloc_ctxt;
//         printf("%p,", i);
//         freeMap[start].push_back(i);
//     }
// }

/* Free Functions */
static void
pre_free(void *wrapcxt, OUT void **user_data)
{
    app_pc start = (app_pc)drwrap_get_arg(wrapcxt, 0);
    if (freeMap.find(start) != freeMap.end()){
        for (app_pc redZone : freeMap[start]){
            if (redMap.find(redZone) != redMap.end()){
                redMap.erase(redZone);
            }
        }
        freeMap.erase(start);
    }
}

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    app_pc towrap_malloc = (app_pc)dr_get_proc_address(mod->handle, "malloc");
    if (towrap_malloc != NULL) {
        drwrap_wrap(towrap_malloc, pre_malloc, post_malloc);
    }

    // app_pc towrap_calloc = (app_pc)dr_get_proc_address(mod->handle, "calloc");
    // if (towrap_calloc != NULL) {
    //     drwrap_wrap(towrap_calloc, pre_calloc, post_calloc);
    // }

    app_pc towrap_free = (app_pc)dr_get_proc_address(mod->handle, "free");
    if (towrap_free != NULL) {
        drwrap_wrap(towrap_free, pre_free, NULL);
    }
}

/* ------------------------------ Helper Wrapper Methods / Objects -------------------------- */


// client want to do
void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, mem_ref_t *ref)
{
    app_pc iter = ref->addr;
    for (; iter < ref->addr + ref->size; iter++){
        if (redMap.find(iter) != redMap.end()){
          printf("RedZone address: %p\n", iter);
          uint64_t key = redMap[iter]; // Malloc Context
          key <<= 32;
          key |= cur_ctxt_hndl; // Current Context
          ctxtMap.insert(key);
        }
    }
}
// dr clean call
void
InsertCleancall(int32_t slot, int32_t num)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0) {
            DoWhatClientWantTodo(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i]);
        }
    }
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

// insert
static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
{
    /* We need two scratch registers */
    reg_id_t reg_mem_ref_ptr, free_reg;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &free_reg) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, free_reg,
                                    reg_mem_ref_ptr)) {
        MINSERT(ilist, where,
                XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                      OPND_CREATE_CCT_INT(0)));
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, addr)),
                opnd_create_reg(free_reg)));

    // store mem_ref_t->size
#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                             opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                             OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
#endif

#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
#endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, free_reg) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{

    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    int num = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
        }
    }
    dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 2,
                         OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(num));
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);
    pt->cur_buf_list =
        (mem_ref_t *)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
  #ifdef ARM_CCTLIB
  char name[MAXIMUM_PATH] = "arm.drcctlib_heap_overflow.log";
  #else
    char name[MAXIMUM_PATH] = "x86.drcctlib_heap_overflow.log";
  #endif

  cout << "Creating log file at: " << name << endl;

  gTraceFile = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
  DR_ASSERT(gTraceFile != INVALID_FILE);
}

static void
ClientExit(void)
{
    unsigned int i = 0;

    for(auto& key : ctxtMap){

        auto malloc_ctxt = (key & 0xFFFFFFFF00000000);
        malloc_ctxt >>= 32;
        auto overflow_ctxt = (key & 0x00000000FFFFFFFF);

        dr_fprintf(gTraceFile, "N0. %d Malloc_ctxt handle: %lld,  Overflow_ctxt handle %lld ====\n", i + 1,
                  malloc_ctxt, overflow_ctxt);

          // drcctlib_print_ctxt_hndl_msg(gTraceFile, cntxt_hndl, false, false);
          dr_fprintf(gTraceFile, "====================================================================="
                     "===========\n");
          dr_fprintf(gTraceFile,  "\n*********** Overflow Context *********\n");
          drcctlib_print_full_cct(gTraceFile, overflow_ctxt, true, false,
                                  MAX_DEPTH_TO_BOTHER);
          dr_fprintf(gTraceFile,  "\n************  Malloc Context *********\n");
          drcctlib_print_full_cct(gTraceFile, malloc_ctxt, true, false,
                                  MAX_DEPTH_TO_BOTHER);
          dr_fprintf(gTraceFile, "====================================================================="
                     "===========\n\n\n");
          ++i;
    }

    dr_close_file(gTraceFile);
    drcctlib_exit();

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_heap_overflow dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_heap_overflow failed to "
                        "unregister in ClientExit");
    }
    drmgr_exit();
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }
    drutil_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_heap_overflow'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drutil");
    }
    if (!drwrap_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_heap_overflow unable to initialize drwrap");
    }
    drmgr_register_module_load_event(module_load_event);

    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_heap_overflow dr_raw_tls_calloc fail");
    }
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback, false);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
