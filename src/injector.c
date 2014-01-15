/*
 * This file is part of the VMI-Honeymon project.
 *
 * 2012-2014 University of Connecticut (http://www.uconn.edu)
 * Tamas K Lengyel <tamas.k.lengyel@gmail.com>
 *
 * VMI-Honeymon is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>

#include "structures.h"
#include "injector.h"
#include "vmi.h"
#include "win-syms.h"

#define PAGE_SIZE 1 << 12
#define KERNEL32 0x80000000
#define KERNEL64 0xFFFFF80000000000

struct injector {
    honeymon_clone_t *clone;
    const char *target_proc;
    vmi_pid_t target_pid;

    win_ver_t winver;
    page_mode_t pm;

    uint8_t ret;
    uint32_t pid, tid;
    uint32_t hProc, hThr;

    vmi_event_t mm_event;
    vmi_event_t ss_event;
    int mm_enabled;
    int ss_enabled;
    addr_t target_rip;
    addr_t process_info;
    addr_t saved_rsp;
    addr_t saved_rip;
    addr_t saved_rax;
    addr_t saved_rcx;
    addr_t saved_rdx;
    addr_t saved_r8;
    addr_t saved_r9;
    int mm_count;
};

struct startup_info_32 {
  uint32_t cb;
  uint32_t lpReserved;
  uint32_t lpDesktop;
  uint32_t lpTitle;
  uint32_t dwX;
  uint32_t dwY;
  uint32_t dwXSize;
  uint32_t dwYSize;
  uint32_t dwXCountChars;
  uint32_t dwYCountChars;
  uint32_t dwFillAttribute;
  uint32_t dwFlags;
  uint16_t wShowWindow;
  uint16_t cbReserved2;
  uint32_t lpReserved2;
  uint32_t hStdInput;
  uint32_t hStdOutput;
  uint32_t hStdError;
};
// __attribute__ ((packed));

struct startup_info_64 {
    uint32_t  cb;
    addr_t lpReserved;
    addr_t lpDesktop;
    addr_t lpTitle;
    uint32_t  dwX;
    uint32_t  dwY;
    uint32_t  dwXSize;
    uint32_t  dwYSize;
    uint32_t  dwXCountChars;
    uint32_t  dwYCountChars;
    uint32_t  dwFillAttribute;
    uint32_t  dwFlags;
    uint16_t   wShowWindow;
    uint16_t   cbReserved2;
    addr_t lpReserved2;
    addr_t hStdInput;
    addr_t hStdOutput;
    addr_t hStdError;
};
// __attribute__ ((packed));

struct process_information_32 {
  uint32_t hProcess;
  uint32_t hThread;
  uint32_t dwProcessId;
  uint32_t dwThreadId;
} __attribute__ ((packed));

struct process_information_64 {
    addr_t hProcess;
    addr_t hThread;
    uint32_t  dwProcessId;
    uint32_t  dwThreadId;
} __attribute__ ((packed));

/*int get_session_id(vmi_instance_t vmi, vmi_pid_t target_pid) {
        addr_t list_head;

        page_mode_t pm=vmi_get_page_mode(vmi);
        win_ver_t winver = vmi_get_winver(vmi);
        size_t pid_offset=vmi_get_offset(vmi, "win_pid");
        size_t tasks_offset=vmi_get_offset(vmi, "win_tasks");

        addr_t current_process, current_list_entry, next_list_entry;
        vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

        list_head = current_process + tasks_offset;
        current_list_entry = list_head;

        if(VMI_FAILURE == vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry)) {
            printf("Failed to read next pointer at 0x%lx before entering loop\n",
            current_list_entry);
            return VMI_FAILURE;
        }

        do {
            current_list_entry = next_list_entry;
            current_process = current_list_entry - tasks_offset;

            addr_t peb, ldr, inloadorder;
            vmi_pid_t pid;
            vmi_read_32_va(vmi, current_process + pid_offset, 0, &pid);
            uint32_t sessionid;

            if(pid==target_pid) {
                vmi_read_addr_va(vmi, current_process+offsets[winver][PM2BIT(pm)][EPROCESS_PEB], 0, &peb);
                vmi_read_32_va(vmi, peb+offsets[winver][PM2BIT(pm)][PEB_SESSIONID], pid, &sessionid);

                return sessionid;
            }

            if(VMI_FAILURE == vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry)) {
                printf("Failed to read next pointer in loop at %lx\n", current_list_entry);
                return VMI_FAILURE;
            }
        } while (next_list_entry != list_head);

    return VMI_FAILURE;
}*/

void hijack_thread(struct injector *injector, vmi_instance_t vmi, unsigned int vcpu, vmi_pid_t pid) {

    printf("Ready to hijack thread of PID %u on vCPU %u!\n", pid, vcpu);

    addr_t cpa = sym2va(vmi, pid, "kernel32.dll", "CreateProcessA");

    printf("CPA @ 0x%lx\n", cpa);

    reg_t fsgs, rbp, rsp, rip, rcx, rdx, rax, r8, r9;
    addr_t stack_base, stack_limit;

    vmi_get_vcpureg(vmi, &rsp, RSP, vcpu);
    vmi_get_vcpureg(vmi, &rip, RIP, vcpu);
    vmi_get_vcpureg(vmi, &rax, RAX, vcpu);
    vmi_get_vcpureg(vmi, &rcx, RCX, vcpu);
    vmi_get_vcpureg(vmi, &rdx, RDX, vcpu);
    vmi_get_vcpureg(vmi, &r8, R8, vcpu);
    vmi_get_vcpureg(vmi, &r9, R9, vcpu);

    if(injector->pm==VMI_PM_LEGACY || injector->pm == VMI_PM_PAE) {
        vmi_get_vcpureg(vmi, &fsgs, FS_BASE, vcpu);
        vmi_get_vcpureg(vmi, &rbp, RBP, vcpu);
        printf("FS: 0x%lx RBP: 0x%lx", fsgs, rbp);
        vmi_read_addr_va(vmi, fsgs+0x4, pid, &stack_base);
        vmi_read_addr_va(vmi, fsgs+0x8, pid, &stack_limit);
    } else {
        vmi_get_vcpureg(vmi, &fsgs, GS_BASE, vcpu);
        printf("GS: 0x%lx ", fsgs);
        vmi_read_addr_va(vmi, fsgs+0x8, pid, &stack_base);
        vmi_read_addr_va(vmi, fsgs+0x10, pid, &stack_limit);
    }

    printf("RSP: 0x%lx. RIP: 0x%lx. RCX: 0x%lx\n", rsp, rip, rcx);
    printf("Stack base: 0x%lx. Limit: 0x%lx\n", stack_base, stack_limit);

    //Push input arguments on the stack
    //CreateProcess(NULL, TARGETPROC,
    //                 NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, pi))

    uint64_t nul64 = 0;
    uint32_t nul32 = 0;
    uint8_t nul8 = 0;
    size_t len = strlen(injector->target_proc);
    addr_t addr = rsp;
    injector->saved_rsp = rsp;
    injector->saved_rip = rip;
    injector->saved_rax = rax;
    injector->saved_rdx = rdx;
    injector->saved_rcx = rcx;
    injector->saved_r8 = r8;
    injector->saved_r9 = r9;

    if(injector->pm==VMI_PM_LEGACY || injector->pm == VMI_PM_PAE) {

        addr -= 0x4; // the stack has to be alligned to 0x4
                     // and we need a bit of extra buffer before the string for \0
        // we just going to null out that extra space fully
        vmi_write_32_va(vmi, addr, pid, &nul32);

        // this string has to be aligned as well!
        addr -= len + 0x4 - (len % 0x4);
        addr_t str_addr = addr;
        vmi_write_va(vmi, addr, pid, (void*)injector->target_proc, len);
        // add null termination
        vmi_write_8_va(vmi, addr+len, pid, &nul8);
        printf("%s @ 0x%lx.\n", injector->target_proc, str_addr);

        struct startup_info_32 si = {0};
        struct process_information_32 pi = {0};

        addr -= sizeof(struct process_information_32);
        injector->process_info = addr;
        vmi_write_va(vmi, addr, pid, &pi, sizeof(struct process_information_32));
        printf("pip @ 0x%lx\n", addr);

        addr -= sizeof(struct startup_info_32);
        addr_t sip = addr;
        vmi_write_va(vmi, addr, pid, &si, sizeof(struct startup_info_32));
        printf("sip @ 0x%lx\n", addr);

        //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
        //
        //First 4 parameters to functions are always passed in registers
        //P1=rcx, P2=rdx, P3=r8, P4=r9
        //5th parameter onwards (if any) passed via the stack

        //p10
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *)&injector->process_info);
        //p9
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *)&sip);
        //p8
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p7
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p6
        uint32_t create_suspended = 0x00000004;
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p5
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p4
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p3
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p2
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *)&str_addr);
        //p1
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);

        // save the return address (RIP)
        addr -=0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *)&rip);

    } else {

        addr -= 0x8; // the stack has to be alligned to 0x8
                     // and we need a bit of extra buffer before the string for \0

        // we just going to null out that extra space fully
        vmi_write_64_va(vmi, addr, pid, &nul64);

        // this string has to be aligned as well!
        addr -= len + 0x8 - (len % 0x8);
        addr_t str_addr = addr;
        vmi_write_va(vmi, addr, pid, (void*)injector->target_proc, len);
        // add null termination
        vmi_write_8_va(vmi, addr+len, pid, &nul8);
        printf("%s @ 0x%lx.\n", injector->target_proc, str_addr);

        struct startup_info_64 si = {0};
        struct process_information_64 pi = {0};

        addr -= sizeof(struct process_information_64);
        injector->process_info = addr;
        vmi_write_va(vmi, addr, pid, &pi, sizeof(struct process_information_64));
        printf("pip @ 0x%lx\n", addr);

        addr -= sizeof(struct startup_info_64);
        addr_t sip = addr;
        vmi_write_va(vmi, addr, pid, &si, sizeof(struct startup_info_64));
        printf("sip @ 0x%lx\n", addr);

        //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
        //
        //First 4 parameters to functions are always passed in registers
        //P1=rcx, P2=rdx, P3=r8, P4=r9
        //5th parameter onwards (if any) passed via the stack

        //p10
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &injector->process_info);
        //p9
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &sip);
        //p8
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        //p7
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        //p6
        uint64_t create_suspended = 0x0000000000000004;
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        //p5
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);

        // allocate 0x20 "homing space"
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);

        //p1
        vmi_set_vcpureg(vmi, 0, RCX, vcpu);
        //p2
        vmi_set_vcpureg(vmi, str_addr, RDX, vcpu);
        //p3
        vmi_set_vcpureg(vmi, 0, R8, vcpu);
        //p4
        vmi_set_vcpureg(vmi, 0, R9, vcpu);

        // save the return address (RIP)
        addr -=0x8;
        vmi_write_64_va(vmi, addr, pid, &rip);
    }

    printf("Return address @ 0x%lx -> 0x%lx. Setting RSP: 0x%lx.\n", addr, rip, addr);

    // Grow the stack and switch execution
    vmi_set_vcpureg(vmi, addr, RSP, vcpu);
    vmi_set_vcpureg(vmi, cpa, RIP, vcpu);

    printf("Done with hijack routine\n");
}

/*void ss_callback(vmi_instance_t vmi, vmi_event_t *event) {
    reg_t rip, cr3, rsp;
    vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);
    page_mode_t pm=vmi_get_page_mode(vmi);
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
    addr_t here = vmi_translate_uv2p(vmi,rip,pid);
    printf("----- Singlestep: CR3 0x%lx PID %u executing RIP 0x%lx\n", cr3, pid, rip);

    if( (PM2BIT(pm)==BIT32 && rip < KERNEL32) || (PM2BIT(pm)==BIT64 && rip < KERNEL64)) {
        printf("Good RIP: 0x%lx\n", rip);
        vmi_clear_event(vmi, event);
        interrupted=1;
    }

}*/

void mm_callback(vmi_instance_t vmi, vmi_event_t *event) {
    struct injector *injector = event->data;
    reg_t rip, cr3, rsp;
    vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
    //int session_id = get_session_id(vmi, pid);

    //printf("----- Memevent: PID %u SessionID %i executing RIP 0x%lx. Target PID: %u. Target RIP: 0x%lx. My event count: %u\n",
    //    pid, session_id, ((event->mem_event.gfn<<12) + event->mem_event.offset), injector->target_pid, injector->target_rip, injector->mm_count);

    vmi_clear_event(vmi, event);

        if( injector->mm_count == 0 && ((PM2BIT(injector->pm)==BIT32 && rip < KERNEL32) || (PM2BIT(injector->pm)==BIT64 && rip < KERNEL64)) ) {
                injector->target_pid = pid;
                injector->target_rip = vmi_translate_uv2p(vmi, rip, pid);

                hijack_thread(injector, vmi, event->vcpu_id, pid);

                vmi_clear_event(vmi, event);
                injector->mm_count++;

            return;
        }

        if(injector->mm_count>0 && pid==injector->target_pid && ((event->mem_event.gfn<<12) + event->mem_event.offset) == injector->target_rip) {

                reg_t rax;
                vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);

                printf("Cought the second memevent for PID %u. RIP: 0x%lx. RAX: %lu\n", pid, event->mem_event.gla, rax);

                printf("Restoring RSP to 0x%lx\n", injector->saved_rsp);
                printf("Restoring RAX to 0x%lx\n", injector->saved_rax);
                printf("Restoring RCX to 0x%lx\n", injector->saved_rcx);
                printf("Restoring RDX to 0x%lx\n", injector->saved_rdx);
                printf("Restoring R8 to 0x%lx\n", injector->saved_r8);
                printf("Restoring R9 to 0x%lx\n", injector->saved_r9);

                vmi_set_vcpureg(vmi, injector->saved_rsp, RSP, event->vcpu_id);
                vmi_set_vcpureg(vmi, injector->saved_rax, RAX, event->vcpu_id);
                vmi_set_vcpureg(vmi, injector->saved_rcx, RCX, event->vcpu_id);
                vmi_set_vcpureg(vmi, injector->saved_rdx, RDX, event->vcpu_id);
                vmi_set_vcpureg(vmi, injector->saved_r8, R8, event->vcpu_id);
                vmi_set_vcpureg(vmi, injector->saved_r9, R9, event->vcpu_id);

                injector->ret = rax;
                injector->mm_enabled = 0;
                injector->clone->interrupted=1;

                if(rax) {
                    printf("-- CreateProcessA SUCCESS --\n");

                    if(PM2BIT(injector->pm)==BIT32) {
                        struct process_information_32 pip = { 0 };
                        vmi_read_va(vmi, injector->process_info, pid, &pip, sizeof(struct process_information_32));
                        printf("\tProcess handle: 0x%x. Thread handle: 0x%x\n", pip.hProcess, pip.hThread);
                        printf("\tPID: %u. TID: %u\n", pip.dwProcessId, pip.dwThreadId);

                        injector->pid = pip.dwProcessId;
                        injector->tid = pip.dwThreadId;
                        injector->hProc = pip.hProcess;
                        injector->hThr = pip.hThread;


                    } else {
                        struct process_information_64 pip = { 0 };
                        vmi_read_va(vmi, injector->process_info, pid, &pip, sizeof(struct process_information_64));
                        printf("\tProcess handle: 0x%lx. Thread handle: 0x%lx\n", pip.hProcess, pip.hThread);
                        printf("\tPID: %u. TID: %u\n", pip.dwProcessId, pip.dwThreadId);

                        injector->pid = pip.dwProcessId;
                        injector->tid = pip.dwThreadId;
                        injector->hProc = pip.hProcess;
                        injector->hThr = pip.hThread;

                    }
                }
            return;
        }

    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
}

void cr3_callback(vmi_instance_t vmi, vmi_event_t *event){

    //printf("CR3 changed to 0x%lx\n", event->reg_event.value);
    struct injector *injector = event->data;
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->reg_event.value);
    //printf("   -- CR3 0x%lx -> PID %u\n", event->reg_event.value, pid);

    addr_t cpa = sym2va(vmi, pid, "kernel32.dll", "CreateProcessA");
    win_ver_t winver = vmi_get_winver(vmi);
    addr_t waitfor = 0;

    if(winver == VMI_OS_WINDOWS_7) {
        waitfor = sym2va(vmi, pid, "kernel32.dll", "WaitForMultipleObjects");
    }

    //printf("SessionID: %u. CPA @ 0x%lx, Waitfor @ 0x%lx.\n", session_id, cpa, waitfor);

    if(pid == injector->target_pid && cpa) {
        if(!injector->target_rip) {

            /*if(!ss_enabled) {
                ss_enabled = 1;
                printf("registering singlestep\n");
                memset(&ss_event, 0, sizeof(vmi_event_t));
                ss_event.type = VMI_EVENT_SINGLESTEP;
                ss_event.callback = ss_callback;
                ss_event.data = &mm_event;
                SET_VCPU_SINGLESTEP(ss_event.ss_event, event->vcpu_id);
                vmi_register_event(vmi, &ss_event);
            }*/

            if(!injector->mm_enabled && waitfor) {
                //printf("PID %u in Session %u registering memevent on 0x%lx\n", pid, session_id, waitfor);
                injector->mm_enabled=1;
                memset(&injector->mm_event, 0, sizeof(vmi_event_t));
                injector->mm_event.type = VMI_EVENT_MEMORY;
                injector->mm_event.mem_event.physical_address = vmi_translate_uv2p(vmi, waitfor, pid);
                injector->mm_event.mem_event.npages = 1;
                injector->mm_event.mem_event.granularity=VMI_MEMEVENT_PAGE;
                injector->mm_event.mem_event.in_access = VMI_MEMACCESS_X;
                injector->mm_event.callback=mm_callback;
                injector->mm_event.data = injector;
                vmi_register_event(vmi, &injector->mm_event);
            }
        } else {
            if(pid == injector->target_pid) {
                if(!injector->mm_enabled) {
                    //printf("Target PID %u registering memevent on target RIP of 0x%lx\n", pid, target_rip);
                    injector->mm_enabled=1;
                    memset(&injector->mm_event, 0, sizeof(vmi_event_t));
                    injector->mm_event.type = VMI_EVENT_MEMORY;
                    injector->mm_event.mem_event.physical_address = injector->target_rip;
                    injector->mm_event.mem_event.npages = 1;
                    injector->mm_event.mem_event.granularity=VMI_MEMEVENT_PAGE;
                    injector->mm_event.mem_event.in_access = VMI_MEMACCESS_X;
                    injector->mm_event.callback=mm_callback;
                    injector->mm_event.data = injector;
                    vmi_register_event(vmi, &injector->mm_event);
                }
            } else {
                if(injector->mm_enabled) {
                    injector->mm_enabled=0;
                    vmi_clear_event(vmi, &injector->mm_event);
                }
            }
        }
    } else {
        //printf("PID %i is executing, not my process!\n", pid);
        if(injector->mm_enabled) {
            injector->mm_enabled=0;
            vmi_clear_event(vmi, &injector->mm_event);
        }
/*
        if(ss_enabled) {
            ss_enabled=0;
            vmi_clear_event(vmi, &ss_event);
        }*/
    }
}

int start_app (honeymon_clone_t *clone, win_ver_t winver, vmi_pid_t pid, const char *app)
{
    printf("Target PID %u to start %s\n", pid, app);

    vmi_instance_t vmi = clone->vmi;
    struct injector injector = { 0 };
    injector.clone = clone;
    injector.target_pid = pid;
    injector.target_proc = app;
    injector.winver = winver;
    injector.pm=vmi_get_page_mode(vmi);

    vmi_event_t cr3_event;
    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.callback = cr3_callback;
    cr3_event.data = &injector;
    vmi_register_event(vmi, &cr3_event);

    printf("Starting event loop\n");

    status_t status = VMI_FAILURE;
    while(!clone->interrupted){
        //printf("Waiting for events...\n");
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            clone->interrupted = -1;
        }
    }

    vmi_clear_event(vmi, &cr3_event);
    vmi_events_listen(vmi,0);

    return injector.ret;
}
