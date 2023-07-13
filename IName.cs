using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace p3ppc.unhardcodedNames;
internal interface IName<T>
{
    public int Id { get; set; }
    public T? All { get; set; }
    public T? Japanese { get; set; }
    public T? English { get; set; }
    public T? Korean { get; set; }
    public T? TraditionalChinese { get; set; }
    public T? SimplifiedChinese { get; set; }
    public T? French { get; set; }
    public T? German { get; set; }
    public T? Italian { get; set; }
    public T? Spanish { get; set; }
}
