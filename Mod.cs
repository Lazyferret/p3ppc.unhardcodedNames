using p3ppc.unhardcodedNames.Configuration;
using p3ppc.unhardcodedNames.Template;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Hooks.ReloadedII.Interfaces;
using Reloaded.Memory;
using Reloaded.Mod.Interfaces;
using Reloaded.Mod.Interfaces.Internal;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using IReloadedHooks = Reloaded.Hooks.ReloadedII.Interfaces.IReloadedHooks;

namespace p3ppc.unhardcodedNames;
/// <summary>
/// Your mod logic goes here.
/// </summary>
public unsafe class Mod : ModBase // <= Do not Remove.
{
    /// <summary>
    /// Provides access to the mod loader API.
    /// </summary>
    private readonly IModLoader _modLoader;

    /// <summary>
    /// Provides access to the Reloaded.Hooks API.
    /// </summary>
    /// <remarks>This is null if you remove dependency on Reloaded.SharedLib.Hooks in your mod.</remarks>
    private readonly IReloadedHooks? _hooks;

    /// <summary>
    /// Provides access to the Reloaded logger.
    /// </summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Entry point into the mod, instance that created this class.
    /// </summary>
    private readonly IMod _owner;

    /// <summary>
    /// Provides access to this mod's configuration.
    /// </summary>
    private Config _configuration;

    /// <summary>
    /// The configuration of the currently executing mod.
    /// </summary>
    private readonly IModConfig _modConfig;

    private Memory _memory;

    private IHook<GetItemNameDelegate> _getItemNameHook;
    private IHook<GetPersonaNameDelegate> _getPersonaNameHook;

    private Dictionary<int, nuint[]> _itemNames = new();
    private Dictionary<int, nuint[]> _personaNames = new();
    private Language* _language;

    public Mod(ModContext context)
    {
        _modLoader = context.ModLoader;
        _hooks = context.Hooks;
        _logger = context.Logger;
        _owner = context.Owner;
        _configuration = context.Configuration;
        _modConfig = context.ModConfig;
        _memory = Memory.Instance;

        if (!Utils.Initialise(_logger, _configuration, _modLoader))
            return;

        Utils.SigScan("E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 0F B6 84 ?? ?? ?? ?? ??", "GetItemName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetItemName function at 0x{funcAddress:X}");
            _getItemNameHook = _hooks.CreateHook<GetItemNameDelegate>(GetItemName, (long)funcAddress).Activate();
        });

        Utils.SigScan("E9 ?? ?? ?? ?? 33 C0 48 83 C4 20 5B C3 8B 05 ?? ?? ?? ??", "GetPersonaName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetPersonaName function at 0x{funcAddress:X}");
            _getPersonaNameHook = _hooks.CreateHook<GetPersonaNameDelegate>(GetPersonaName, (long)funcAddress).Activate();
        });

        Utils.SigScan("48 63 05 ?? ?? ?? ?? 0F 57 F6", "LanguagePtr", address =>
        {
            var languageAddress = Utils.GetGlobalAddress(address + 3);
            Utils.LogDebug($"Found Language at 0x{languageAddress:X}");
            _language = (Language*)languageAddress;
        });

        _modLoader.ModLoading += OnModLoading;

        foreach (var mod in _modLoader.GetActiveMods().Where(x => x.Generic.ModDependencies.Contains(_modConfig.ModIcon)))
            AddNamesFromDir(_modLoader.GetDirectoryForModId(mod.Generic.ModId));
    }

    private void OnModLoading(IModV1 mod, IModConfigV1 config)
    {
        if (config.ModDependencies.Contains(_modConfig.ModId))
            AddNamesFromDir(_modLoader.GetDirectoryForModId(config.ModId));
    }

    private void AddNamesFromDir(string dir)
    {
        AddNamesFromDir(dir, ref _itemNames, "ItemNames.json");
        AddNamesFromDir(dir, ref _personaNames, "PersonaNames.json");
    }

    private void AddNamesFromDir(string dir, ref Dictionary<int, nuint[]> namesDict, string nameFile)
    {
        var namesPath = Path.Combine(dir, nameFile);
        if (!File.Exists(namesPath)) return;

        var json = File.ReadAllText(namesPath);
        var names = JsonSerializer.Deserialize<List<Name>>(json);
        if (names == null)
        {
            Utils.LogError($"Error parsing names from {namesPath}");
            return;
        }

        foreach(var name in names)
        {
            var id = name.Id;
            var languages = Enum.GetNames(typeof(Language));

            if(!namesDict.ContainsKey(id))
                namesDict[id] = new nuint[languages.Length];

            for (int i = 0; i < languages.Length; i++)
            {
                var langName = name.GetType().GetProperty(languages[i]).GetValue(name);
                if (langName != null)
                {
                    var bytes = Encoding.ASCII.GetBytes((string)langName);
                    var address = _memory.Allocate((nuint)bytes.Length).Address;
                    namesDict[id][i] = address;
                    _memory.WriteRaw(address, bytes);
                }
            }
        }
    }

    private nuint GetItemName(short item)
    {
        if (!_itemNames.TryGetValue(item, out var name))
        {
            return _getItemNameHook.OriginalFunction(item);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getItemNameHook.OriginalFunction(item);

        return langName;
    }

    private nuint GetPersonaName(short persona)
    {
        if (!_personaNames.TryGetValue(persona, out var name))
        {
            return _getPersonaNameHook.OriginalFunction(persona);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getPersonaNameHook.OriginalFunction(persona);

        return langName;
    }

    [Function(CallingConventions.Microsoft)]
    private delegate nuint GetItemNameDelegate(short item);

    [Function(CallingConventions.Microsoft)]
    private delegate nuint GetPersonaNameDelegate(short persona);

    private enum Language : int
    {
        Japanese,
        English,
        Korean,
        TraditionalChinese,
        SimplifiedChinese,
        French,
        German,
        Italian,
        Spanish
    }

    #region Standard Overrides
    public override void ConfigurationUpdated(Config configuration)
    {
        // Apply settings from configuration.
        // ... your code here.
        _configuration = configuration;
        _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
    }
    #endregion

    #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    public Mod() { }
#pragma warning restore CS8618
    #endregion
}