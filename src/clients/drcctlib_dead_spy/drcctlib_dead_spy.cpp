/*
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstddef>
#include <iostream>

#include "dr_api.h"
#include "shadow_memory.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"
#include <unordered_map>
#include <unordered_set>
#include <queue>

#define MAX_DEPTH_TO_BOTHER 10
#define MAXFREQ 100
#define REF_WRITE 1

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("dead_spy", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("dead_spy", format, \
                                          ##args)

static file_t gTraceFile;

struct stateWord {
    context_handle_t ctxt; // Probable dead context
    ptr_int_t isWritten;
    stateWord(context_handle_t ctxt, int isWritten) : ctxt(ctxt), isWritten(isWritten) {}
} __attribute__((packed));

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static int tls_idx;
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
    ptr_int_t state = 0;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
    TlsShadowMemory<stateWord>* shdwMemory; // Shdw memory to store state information
    unordered_map<uint64_t, uint64_t>* memMap; // <{dead_context, killing_context}, frequency>
    unordered_map<uint64_t, uint64_t>* regMap; // <{dead_context, killing_context}, frequency>
    unordered_map<reg_id_t, stateWord>* regState; // State of registers
} per_thread_t;

// {<Dead Ctx, Killing Ctx>, frequency}
using q_pair = pair<uint64_t, uint64_t>;

struct pq_cmp{
   bool operator()(const q_pair& a, const q_pair& b){
      return a.second < b.second;
   }
};

#define TLS_MEM_REF_BUFF_SIZE 100

// client want to do
void
FindDeadStores_Memory(void *drcontext, context_handle_t cur_ctxt_hndl, mem_ref_t *ref, per_thread_t *pt)
{
      //std::cout << " Find Dead Stores " << endl;
      auto addr = (size_t)ref->addr;
      auto shdwVal = pt->shdwMemory->GetShadowAddress(addr);

      // Dead Write Identified
      if (shdwVal && (shdwVal->isWritten & ref->state & 1) == 1){
          uint64_t key = shdwVal->ctxt;
          key <<= 32;
          key |= cur_ctxt_hndl; // Killing Context
          if (pt->memMap->find(key) == pt->memMap->end()){
              pt->memMap->emplace(key, 0);
          }
          pt->memMap->at(key)++;
      }

      if (!shdwVal){
          shdwVal = pt->shdwMemory->GetOrCreateShadowAddress(addr);
      }

      shdwVal->ctxt = cur_ctxt_hndl;
      shdwVal->isWritten = ref->state;

      return ;
}
// dr clean call
void
InsertCleancall_memory(int32_t slot, int32_t num)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0) {
            FindDeadStores_Memory(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i], pt);
        }
    }
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

void
InsertCleancall_register(int32_t slot, reg_id_t reg, int32_t state){

    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);

    // Dead Write Identified
    if (pt->regState->find(reg) != pt->regState->end()
                && ((state & pt->regState->at(reg).isWritten & REF_WRITE) == REF_WRITE)){
        uint64_t key = pt->regState->at(reg).ctxt;
        key <<= 32;
        key |= cur_ctxt_hndl; // Killing Context
        // printf("Destination Reg in Clean Call: %d, Dead: %d, Killing: %d \n", reg, pt->regState->at(reg).ctxt, cur_ctxt_hndl);
        //std::cout << "Dead Context: " << pt->regState->at(reg).ctxt << " Killing Context: " << cur_ctxt_hndl << std::endl;
        if (pt->regMap->find(key) == pt->regMap->end()){
            pt->regMap->emplace(key, 0);
        }
        ++pt->regMap->at(key);
    }

    if (pt->regState->find(reg) == pt->regState->end()){
       stateWord word(cur_ctxt_hndl, state);
       pt->regState->emplace(reg, word);
    }
    else{
       pt->regState->at(reg).isWritten = state;
       pt->regState->at(reg).ctxt = cur_ctxt_hndl;
    }
}

// insert
static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref, bool writeState)
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

    // store mem_ref_t->state
    if (writeState){
        MINSERT(ilist, where,
                 XINST_CREATE_store(
                   drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, state)),
                   OPND_CREATE_INT32(1)));
    }
    else{
       MINSERT(ilist, where,
               XINST_CREATE_store(
                 drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, state)),
                 OPND_CREATE_INT32(0)));
    }


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
        opnd_t op = instr_get_src(instr, i);
        if (opnd_is_memory_reference(op)) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i), false);
        }

        // Loop over any number of registers present in a operand
        int num_temp = opnd_num_regs_used(op);
        for (int j = 0; j < num_temp; j++){
            auto reg = opnd_get_reg_used(op, j);
            // printf("Source Reg: %d \n", reg);
            dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall_register, false, 3,
                                OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(reg), OPND_CREATE_CCT_INT(0));
        }
    }

    for (int i = 0; i < instr_num_dsts(instr); i++) {
        opnd_t op = instr_get_dst(instr, i);
        int isReg = 1;
        if (opnd_is_memory_reference(op)) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i), true);
            isReg = 0;
        }
        //auto reg = opnd_get_reg(op);
        int num_temp = opnd_num_regs_used(op);
        for (int j = 0; j < num_temp; j++){
            auto reg = opnd_get_reg_used(op, j);
            // printf("Destination Reg: %d \n", reg);
            dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall_register, false, 3,
                                 OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(reg), OPND_CREATE_CCT_INT(isReg));
        }
    }
    dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall_memory, false, 2,
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

    pt->shdwMemory = new TlsShadowMemory<stateWord>();
    pt->memMap = new unordered_map<uint64_t, uint64_t>();
    pt->regMap = new unordered_map<uint64_t, uint64_t>();
    pt->regState = new unordered_map<reg_id_t, stateWord>();
}

static priority_queue<q_pair, vector<q_pair>, pq_cmp>
Top100Freq(unordered_map<uint64_t, uint64_t>* ump, int& total_occurences){

    priority_queue<q_pair, vector<q_pair>, pq_cmp> Q;

    total_occurences = 0;

    for (auto val : *(ump)){
        if (Q.size() < 10){
            Q.push(val);
        }
        else{
            if (Q.top().second < val.second){
              Q.pop();
              Q.push(val);
            }
        }
        total_occurences += val.second;
    }

    return Q;
}

static void
print_stats(priority_queue<q_pair, vector<q_pair>, pq_cmp>& Q, const string& name, int dead_occ){

  dr_fprintf(gTraceFile, "================================================ Total Dead Occurences for %s : %d \
  ========================================= \n\n", name.c_str(), dead_occ);

  unsigned int i = 0;

  while (!Q.empty()) {

      auto dead_ctxt = (Q.top().first & 0xFFFFFFFF00000000);
      dead_ctxt >>= 32;
      auto killing_ctxt = (Q.top().first & 0x00000000FFFFFFFF);

      dr_fprintf(gTraceFile, "N0. %d  Dead Context: %lld,  Killing Context: %lld, Frequency: %d ==== \n", i + 1,
                dead_ctxt, killing_ctxt, Q.top().second);

      //drcctlib_print_ctxt_hndl_msg(gTraceFile, cntxt_hndl, false, false);
      dr_fprintf(gTraceFile,
                 "====================================================================="
                 "===========\n");
      drcctlib_print_full_cct(gTraceFile, dead_ctxt, true, false,
                              MAX_DEPTH_TO_BOTHER);
      dr_fprintf(gTraceFile,
                 "***********************\n");
      drcctlib_print_full_cct(gTraceFile, killing_ctxt, true, false,
                             MAX_DEPTH_TO_BOTHER);
      dr_fprintf(gTraceFile,
                 "====================================================================="
                 "===========\n\n\n");
      ++i;
      Q.pop();
  }
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    int dead_occ;

    auto Q = Top100Freq(pt->memMap, dead_occ);

    print_stats(Q, "Memory", dead_occ);

    Q = Top100Freq(pt->regMap, dead_occ);

    print_stats(Q, "Registers", dead_occ);



    delete pt->shdwMemory;
    delete pt->memMap;
    delete pt->regMap;
    delete pt->regState;

    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
  #ifdef ARM_CCTLIB
      char name[MAXIMUM_PATH] = "arm.drcctlib_dead_spy.log";
  #else
      char name[MAXIMUM_PATH] = "x86.drcctlib_dead_spy.log";
  #endif

    cout << "Creating log file at: " << name << endl;

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
}



static void
ClientExit(void)
{
    // add output module here
    dr_close_file(gTraceFile);
    drcctlib_exit();

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_dead_spy dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_dead_spy failed to "
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
    dr_set_client_name("DynamoRIO Client 'drcctlib_dead_spy'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_dead_spy "
                              "unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_dead_spy "
                              "unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_dead_spy "
                              "unable to initialize drutil");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_dead_spy "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_dead_spy dr_raw_tls_calloc fail");
    }
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback, false);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
