-- Lets the President reject (delete) an account that is waiting for approval.
-- Run this once in the Supabase SQL Editor.
--
-- The public (anon) key cannot DELETE from public.accounts, and it should stay
-- that way: otherwise anyone could delete accounts. This function runs with the
-- owner's rights instead, but only after the President's password checks out.

create or replace function public.smfa_reject_account(p_pw text, p_target text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  res text;
begin
  -- Reuse the existing login check (also counts wrong attempts toward the lockout)
  res := trim(both '"' from public.smfa_login('President', p_pw)::text);
  if res is distinct from 'ok' then
    return coalesce(res, 'bad');
  end if;

  -- Only accounts that are still waiting can be rejected
  delete from public.accounts where username = p_target and approved = false;
  if not found then
    return 'gone';
  end if;

  delete from public.wallets where username = p_target;
  return 'ok';
end;
$$;

revoke all on function public.smfa_reject_account(text, text) from public;
grant execute on function public.smfa_reject_account(text, text) to anon, authenticated;
