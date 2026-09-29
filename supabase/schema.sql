-- UC Network staff management database
-- Safe to rerun: existing tables are kept and policies are recreated.

create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.employees (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  designation text not null default '',
  employee_no text not null unique,
  photo_url text not null default '',
  monthly_salary numeric(12,2) not null default 0
    check (monthly_salary >= 0),
  status text not null default 'On Service'
    check (status in ('On Service', 'Resigned')),
  created_at timestamptz not null default now()
);

create table if not exists public.attendance (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null
    references public.employees(id) on delete cascade,
  work_date date not null,
  status text not null
    check (status in ('Present', 'Absent', 'Paid Off', 'Unpaid Off')),
  unique (employee_id, work_date)
);

create table if not exists public.advances (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null
    references public.employees(id) on delete cascade,
  amount numeric(12,2) not null check (amount > 0),
  advance_date date not null default current_date,
  note text not null default ''
);

create table if not exists public.payroll (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null
    references public.employees(id) on delete cascade,
  pay_month text not null,
  unpaid_days integer not null default 0 check (unpaid_days >= 0),
  advance_deduction numeric(12,2) not null default 0
    check (advance_deduction >= 0),
  net_salary numeric(12,2) not null default 0
    check (net_salary >= 0),
  paid boolean not null default false,
  updated_at timestamptz not null default now(),
  unique (employee_id, pay_month)
);

-- The website checks this function to confirm the signed-in user is an admin.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.admins
    where user_id = (select auth.uid())
  );
$$;

grant execute on function public.is_admin() to authenticated;

-- Turn on row-level security.
alter table public.admins enable row level security;
alter table public.employees enable row level security;
alter table public.attendance enable row level security;
alter table public.advances enable row level security;
alter table public.payroll enable row level security;

-- Do not allow users to access the admin list directly.
revoke all on public.admins from anon, authenticated;

-- Allow signed-in users to make requests; row-level security limits access
-- to the administrator account.
grant select, insert, update, delete
on public.employees, public.attendance, public.advances, public.payroll
to authenticated;

-- Re-create admin-only access policies.
drop policy if exists "Admins manage employees" on public.employees;
create policy "Admins manage employees"
on public.employees for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "Admins manage attendance" on public.attendance;
create policy "Admins manage attendance"
on public.attendance for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "Admins manage advances" on public.advances;
create policy "Admins manage advances"
on public.advances for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "Admins manage payroll" on public.payroll;
create policy "Admins manage payroll"
on public.payroll for all to authenticated
using (public.is_admin())
with check (public.is_admin());

-- Improve common lookups.
create index if not exists attendance_date_idx
  on public.attendance (work_date);

create index if not exists attendance_employee_idx
  on public.attendance (employee_id);

create index if not exists advances_employee_idx
  on public.advances (employee_id);

create index if not exists payroll_month_idx
  on public.payroll (pay_month);
