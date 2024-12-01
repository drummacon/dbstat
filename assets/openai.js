import OpenAI from "openai";
import dotenv from "dotenv";
dotenv.config();
const apiKey = process.env.OPENAI_API_KEY;
const openai = new OpenAI({ apiKey });

export default async function getSecurityCommands() {
  try {
    if (!apiKey) {
      console.error("OpenAI API key is not set in the environment variables.");
      return [];
    }
    
    const prompt = `Generate a list of 5 random but critical lesser known macOS (13.0+) security commands. Respond with a JSON array where each object has 'description' and 'command' fields. For example: [{"description": "Check firewall status", "command": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"}]`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7,
      max_tokens: 1500
    });

    const assistantMessage = completion.choices[0].message.content.trim();
    const jsonMatch = assistantMessage.match(/\[[\s\S]*\]/);
    
    if (jsonMatch) {
      try {
        const commands = JSON.parse(jsonMatch[0]);
        return commands.filter(cmd => 
          cmd && 
          typeof cmd === 'object' && 
          typeof cmd.description === 'string' && 
          typeof cmd.command === 'string'
        );
      } catch (parseError) {
        console.error('Error parsing JSON:', parseError);
        console.error('Matched content:', jsonMatch[0]);
        return [];
      }
    }

    console.error('No valid JSON array found in response');
    console.error('Full response:', assistantMessage);
    return [];
    
  } catch (error) {
    console.error('OpenAI Error:', error);
    return [];
  }
}