from __future__ import annotations

import io
from urllib.parse import quote

import aiohttp
import discord
from redbot.core import Config, commands

MAX_BYTES = 100 * 1024 * 1024
ALLOWED_SUFFIXES = (".log", ".txt", ".yml", ".yaml") + tuple(f".{n}" for n in range(1, 10))


class ScanPrompt(discord.ui.View):
    def __init__(self, cog: "LogScan", author_id: int, attachment: discord.Attachment):
        super().__init__(timeout=120)
        self.cog = cog
        self.author_id = author_id
        self.attachment = attachment

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.author_id:
            return True
        await interaction.response.send_message("Only the person who posted the log can choose.", ephemeral=True)
        return False

    @discord.ui.button(label="Scan log", style=discord.ButtonStyle.primary, emoji="🔎")
    async def scan(self, interaction: discord.Interaction, _button: discord.ui.Button):
        await interaction.response.defer()
        for item in self.children:
            item.disabled = True
        await interaction.edit_original_response(view=self)
        try:
            url = await self.cog.scan_attachment(self.attachment)
        except (aiohttp.ClientError, ValueError) as exc:
            await interaction.followup.send(f"I couldn't scan that file: {exc}")
            return
        await interaction.followup.send(
            f"Scan complete: <{url}>\n"
            "Anyone with this link can view the log and use its **Delete log** button."
        )

    @discord.ui.button(label="No thanks", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, _button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(content="Log scan skipped.", view=self)


class LogScan(commands.Cog):
    """Detect and submit Kometa log attachments."""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=0x4C4F475343414E, force_registration=True)
        self.config.register_global(url="https://logscan.kometa.team", api_key="")

    @commands.Cog.listener()
    async def on_message_without_command(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return
        attachments = [
            item for item in message.attachments
            if item.filename.lower().endswith(ALLOWED_SUFFIXES)
        ]
        if not attachments:
            return
        attachment = attachments[0]
        if attachment.size > MAX_BYTES:
            await message.reply("That log is larger than the 100 MiB scanner limit.", mention_author=False)
            return
        await message.reply(
            f"Would you like me to scan `{attachment.filename}`?",
            view=ScanPrompt(self, message.author.id, attachment),
            mention_author=False,
        )

    async def scan_attachment(self, attachment: discord.Attachment) -> str:
        base_url = (await self.config.url()).rstrip("/")
        api_key = await self.config.api_key()
        if not api_key:
            raise ValueError("the cog API key has not been configured")
        content = await attachment.read()
        if len(content) > MAX_BYTES:
            raise ValueError("the attachment exceeds 100 MiB")
        form = aiohttp.FormData()
        form.add_field(
            "log",
            io.BytesIO(content),
            filename=attachment.filename,
            content_type=attachment.content_type or "text/plain",
        )
        headers = {"Authorization": f"Bearer {api_key}"}
        timeout = aiohttp.ClientTimeout(total=300)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"{base_url}/api/bot/scan", data=form, headers=headers) as response:
                payload = await response.json(content_type=None)
                if response.status != 200:
                    raise ValueError(payload.get("error", f"server returned HTTP {response.status}"))
        return f"{payload['result_url']}#delete={quote(payload['delete_token'], safe='')}"

    @commands.group(name="logscanset")
    @commands.is_owner()
    async def logscan_settings(self, ctx: commands.Context):
        """Configure the LogScan service."""

    @logscan_settings.command(name="url")
    async def set_url(self, ctx: commands.Context, url: str):
        await self.config.url.set(url.rstrip("/"))
        await ctx.send("LogScan URL updated.")

    @logscan_settings.command(name="apikey")
    async def set_api_key(self, ctx: commands.Context, api_key: str):
        await self.config.api_key.set(api_key)
        try:
            await ctx.message.delete()
        except discord.HTTPException:
            pass
        await ctx.send("LogScan API key updated.", delete_after=10)
