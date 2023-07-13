using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace p3ppc.unhardcodedNames;
internal class CharacterName : IName
{
    public int Id { get; set; }
    public NameParts? Japanese { get; set; }
    public NameParts? English { get; set; }
    public NameParts? Korean { get; set; }
    public NameParts? TraditionalChinese { get; set; }
    public NameParts? SimplifiedChinese { get; set; }
    public NameParts? French { get; set; }
    public NameParts? German { get; set; }
    public NameParts? Italian { get; set; }
    public NameParts? Spanish { get; set; }

}

internal class NameParts
{
    public string? First { get; set; }
    public string? Last { get; set; }
    public string? Full { get; set; }
}
